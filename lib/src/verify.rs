use anyhow::Result;
use isomdl;
use isomdl::definitions::helpers::non_empty_map::NonEmptyMap;
use isomdl::definitions::oid4vp::DeviceResponse;
use isomdl::presentation::reader::Error as IsomdlError;
use oidc4vp::mdl_request::ClientMetadata;
use oidc4vp::mdl_request::RequestObject;
use oidc4vp::mdl_request::{MetaData, PresDef};
use oidc4vp::presentment::Verify;
use oidc4vp::utils::Openid4vpError;
use oidc4vp::{
    presentation_exchange::{
        Constraints, ConstraintsField, InputDescriptor, PresentationDefinition,
    },
    utils::NonEmptyVec,
};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use josekit::jwk::Jwk;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnattendedSessionManager {
    pub epk: Jwk,
    pub esk: Jwk,
}

impl UnattendedSessionManager {
    pub fn new(epk: Jwk, esk: Jwk) -> Result<Self> {
        Ok(UnattendedSessionManager { epk, esk })
    }
}

pub trait ReaderSession {
    fn handle_response(
        &mut self,
        device_response: DeviceResponse,
    ) -> Result<BTreeMap<String, Value>, IsomdlError> {
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
        let response = device_response;
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

impl ReaderSession for UnattendedSessionManager {}

impl Verify for UnattendedSessionManager {
    fn mdl_request(
        &self,
        requested_fields: NonEmptyMap<String, NonEmptyMap<Option<String>, Option<bool>>>,
        client_id: String,
        response_uri: String,
        presentation_id: String,
        response_mode: String,
        client_metadata: ClientMetadata,
        e_reader_key_bytes: String,
    ) -> Result<RequestObject, Openid4vpError> {
        let presentation_definition =
            mdl_presentation_definition(requested_fields, presentation_id)?;

        Ok(RequestObject {
            aud: "https://self-issued.me/v2".to_string(), // per openid4vp chapter 5.6
            response_type: "vp_token".to_string(),
            client_id,
            client_id_scheme: Some("x509_san_uri".to_string()),
            response_uri: Some(response_uri),
            scope: None,
            state: None,
            presentation_definition: PresDef::PresentationDefinition {
                presentation_definition,
            },
            client_metadata: MetaData::ClientMetadata { client_metadata },
            response_mode: Some(response_mode),
            nonce: Some(e_reader_key_bytes),
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
    namespaces: NonEmptyMap<String, NonEmptyMap<Option<String>, Option<bool>>>,
    presentation_id: String,
) -> Result<PresentationDefinition, Openid4vpError> {
    let input_descriptors = build_input_descriptors(namespaces);
    Ok(PresentationDefinition {
        id: presentation_id,
        input_descriptors,
        name: None,
        purpose: None,
        format: None,
    })
}

//TODO: allow for specifying the algorithm
fn build_input_descriptors(
    namespaces: NonEmptyMap<String, NonEmptyMap<Option<String>, Option<bool>>>,
) -> Vec<InputDescriptor> {
    let path_base = "$['org.iso.18013.5.1']";

    let input_descriptors: Vec<InputDescriptor> = namespaces
        .iter()
        .map(|namespace| {
            let format = json!({
            "mso_mdoc": {
                "alg": [
                    "ES256"
                    //TODO: add all supported algorithms
                ]
            }});
            let mut namespace_fields = BTreeMap::from(namespace.1.to_owned());
            namespace_fields.retain(|k, _v| k.is_some());

            let fields: Vec<ConstraintsField> = namespace_fields
                .iter()
                .map(|field| {
                    ConstraintsField {
                        //safe unwrap since none values are removed above
                        path: NonEmptyVec::new(format!(
                            "{}['{}']",
                            path_base,
                            field.0.as_ref().unwrap().to_owned()
                        )),
                        id: None,
                        purpose: None,
                        name: None,
                        filter: None,
                        optional: None,
                        intent_to_retain: *field.1,
                    }
                })
                .collect();

            let constraints = Constraints {
                fields: Some(fields),
                limit_disclosure: Some(
                    oidc4vp::presentation_exchange::ConstraintsLimitDisclosure::Required,
                ),
            };

            InputDescriptor {
                id: "org.iso.18013.5.1.mDL ".to_string(),
                name: None,
                purpose: None,
                format: Some(format),
                constraints: Some(constraints),
                schema: None,
            }
        })
        .collect();

    input_descriptors
}

pub fn decrypted_authorization_response(response: String, state: UnattendedSessionManager) -> Result<Vec<u8>, Openid4vpError>{
    let decrypter = josekit::jwe::ECDH_ES.decrypter_from_jwk(&state.esk)?;
    let (payload, _header) = josekit::jwt::decode_with_decrypter(&response, &decrypter)?;
    let vp_token = payload.claim("vp_token");
    if let Some(token) = vp_token {
        match token {
            Value::String(s) => {
                let result = base64url::decode(s).unwrap();
                return Ok(result)
            },
            _ => {
                return Err(Openid4vpError::UnrecognizedField)
            }
        }
    } else {
        Err(Openid4vpError::Empty)
    }
}
