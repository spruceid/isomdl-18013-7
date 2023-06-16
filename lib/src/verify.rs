use oidc4vp::presentment::Verify;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use oidc4vp::{utils::Error, jar::RequestObject};
use oidc4vp::{
    presentation_exchange::{
        Constraints, ConstraintsField, InputDescriptor,
        PresentationDefinition,
    },
    utils::NonEmptyVec,
};
use serde_json::{json, Value};
use isomdl::definitions::helpers::NonEmptyMap;
use std::collections::BTreeMap;
use oidc4vp::mdl_request::ClientMetadata;
use isomdl;
use isomdl::definitions::oid4vp::DeviceResponse;
use isomdl::presentation::reader::Error as IsomdlError;
use crate::isomdl::presentation::reader::ReaderSession;
use serde_cbor::Value as CborValue;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnattendedSessionManager {
    pub device_response: DeviceResponse,
}

impl UnattendedSessionManager {
    pub fn new(device_response: DeviceResponse) -> Result<Self> {
        Ok(UnattendedSessionManager {device_response})
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnattendedSessionManagerInit {
}

impl UnattendedSessionManagerInit {
    pub fn new() -> Result<Self> {
        Ok(UnattendedSessionManagerInit{})
    }
}

impl ReaderSession for UnattendedSessionManager {
    fn handle_response(&mut self) -> Result<BTreeMap<String, Value>, IsomdlError> {
        // TODO: Mdoc authentication.
        //
        // 1. As part of mdoc response, mdl produces `DeviceAuth`, which is either a `DeviceSignature` or
        //    a `DeviceMac`.
        //
        // 2. The reader must verify that `DeviceKey` in the MSO is the key that generated the
        //    `DeviceAuth`.
        //
        // 3. The reader must verify that the `DeviceKey` is authorized by `KeyAuthorizations` to
        //    sign over the data elements present in `DeviceNameSpaces`.
        //
        // 4. The reader must verify that the `DeviceKey` is the subject of the x5chain, and that the
        //    x5chain is consistent and issued by a trusted source.
        let mut parsed_response = BTreeMap::<String, serde_json::Value>::new();
        let response = self.device_response.clone();
        response
            .documents
            .ok_or(IsomdlError::DeviceTransmissionError)?
            .into_inner()
            .into_iter()
            .find(|doc| doc.doc_type == "org.iso.18013.5.1.mDL")
            .ok_or(IsomdlError::DocumentTypeError)?
            .issuer_signed
            .namespaces
            .ok_or(IsomdlError::NoMdlDataTransmission)?
            .into_inner()
            .remove("org.iso.18013.5.1")
            .ok_or(IsomdlError::IncorrectNamespace)?
            .into_inner()
            .into_iter()
            .map(|item| item.into_inner())
            .for_each(|item| {
                let value = parse_response(item.element_value.clone());
                if let Ok(val) = value {
                    parsed_response.insert(item.element_identifier, val);
                }
            });
        Ok(parsed_response)
}
}

impl Verify for UnattendedSessionManagerInit {
    fn mdl_request(&self, requested_fields: NonEmptyMap< String, NonEmptyMap<Option<String>, Option<bool>>> , client_id: String, redirect_uri: String, presentation_id: String, response_mode: String, client_metadata: ClientMetadata) -> Result<RequestObject, Error>{
        let presentation_definition = mdl_presentation_definition(requested_fields, presentation_id)?;
    
        Ok(RequestObject{
            aud: "https://self-issued.me/v2".to_string(),  // per openid4vp chapter 5.6
            response_type: "vp_token".to_string(),
            client_id: client_id.clone(),
            client_id_scheme: Some("ISO_X509".to_string()),
            redirect_uri: Some(redirect_uri),
            scope: Some("openid".to_string()), // I think it could also be None
            state:"".to_string(), 
            presentation_definition: Some(presentation_definition),
            presentation_definition_uri: None,
            client_metadata,
            client_metadata_uri: None,
            response_mode: Some(response_mode),
            nonce: Some(client_id),
            supported_algorithm: "ES256".to_string()
        })
    }
}

fn parse_response(value: CborValue) -> Result<Value, IsomdlError> {
    match value {
        CborValue::Text(s) => Ok(Value::String(s)),
        CborValue::Tag(_t, v) => {
            if let CborValue::Text(d) = *v {
                Ok(Value::String(d))
            } else {
                Err(IsomdlError::ParsingError)
            }
        }
        CborValue::Array(v) => {
            let mut array_response = Vec::<Value>::new();
            for a in v {
                let r = parse_response(a)?;
                array_response.push(r);
            }
            Ok(json!(array_response))
        }
        CborValue::Map(m) => {
            let mut map_response = BTreeMap::<String, String>::new();
            for (key, value) in m {
                if let CborValue::Text(k) = key {
                    let parsed = parse_response(value)?;
                    if let Value::String(x) = parsed {
                        map_response.insert(k, x);
                    }
                }
            }
            let json = json!(map_response);
            Ok(json)
        }
        CborValue::Bytes(b) => Ok(json!(b)),
        CborValue::Bool(b) => Ok(json!(b)),
        CborValue::Integer(i) => Ok(json!(i)),
        _ => Err(IsomdlError::ParsingError),
    }
}

fn mdl_presentation_definition(
    namespaces: NonEmptyMap< String, NonEmptyMap<Option<String>, Option<bool>>>,
    presentation_id: String
) -> Result<PresentationDefinition, Error> {
    let input_descriptors = build_input_descriptors(namespaces);
    Ok(PresentationDefinition{
        id: presentation_id,
        input_descriptors: input_descriptors,
        name: None,
        purpose: None,
        format: None,
    })
}

fn build_input_descriptors(namespaces: NonEmptyMap< String, NonEmptyMap<Option<String>, Option<bool>>>) -> Vec<InputDescriptor>{
    let path_base = "$.mdoc.";

    let doc_type_filter = json!({
            "type": "string",
            "const": "org.iso.18013.5.1.mDL"
        });

    let input_descriptors: Vec<InputDescriptor> = namespaces.iter().map(|namespace| {
        let namespace_filter = json!({
            "type": "string",
            "const": namespace.0
        });

        let format = json!({
            "mso_mdoc": {
                "alg": [
                    "EdDSA",
                    "ES256"
                    //TODO add all supported algorithms
                ]
            }});
        let namespace_fields = namespace.1.to_owned();
        let mut fields: Vec<ConstraintsField> =  namespace_fields.iter().map(|field| {
            ConstraintsField { 
                path: NonEmptyVec::new(format!("{}{}", path_base, field.0.as_ref().unwrap().to_owned())),
                 id: None,
                 purpose:None,
                 name:None,
                filter: None,
                optional: None,
                intent_to_retain: *field.1 
            
            }
        }).collect();

        fields.push(ConstraintsField {
            path: NonEmptyVec::new(format!("{}{}", path_base, "doc_type")),
            id: None,
            purpose: None,
            name: None,
            filter: Some(doc_type_filter.clone()),
            optional: None,
            intent_to_retain: None,
        });
    
        fields.push(ConstraintsField {
            path: NonEmptyVec::new(format!("{}{}", path_base, "namespace")),
            id: None,
            purpose: None,
            name: None,
            filter: Some(namespace_filter),
            optional: None,
            intent_to_retain: None,
        });

        let constraints = Constraints{
            fields: Some(fields),
            limit_disclosure: None,
        };

        InputDescriptor{ 
            id: "mDL".to_string(),
            name: None,
            purpose: None,
            format: Some(format),
            constraints: Some(constraints),
            schema: None }
    }).collect();

    input_descriptors

}
