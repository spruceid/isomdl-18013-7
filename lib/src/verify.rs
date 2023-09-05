use crate::present::UnattendedDeviceAuthentication;
use crate::present::UnattendedSessionTranscript;
use anyhow::Result;
use elliptic_curve::generic_array::GenericArray;
use isomdl;
use isomdl::definitions::helpers::non_empty_map::NonEmptyMap;
use isomdl::definitions::helpers::Tag24;
use isomdl::definitions::oid4vp::DeviceResponse;
use isomdl::definitions::DeviceAuth;
use isomdl::definitions::Mso;
use isomdl::presentation::reader::Error as IsomdlError;
use josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter;
use josekit::jwk::Jwk;
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
use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use p256::NistP256;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_json::{json, Value};
use ssi::jwk::Params;
use ssi::jwk::JWK as SsiJwk;
use std::collections::BTreeMap;
//use x509_cert::der::Decode;
//use p256::pkcs8::DecodePublicKey;

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
        session_transcript: UnattendedSessionTranscript,
    ) -> Result<BTreeMap<String, Value>, Openid4vpError> {
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
        let document = device_response
            .documents
            .clone()
            .ok_or(IsomdlError::DeviceTransmissionError)?
            .into_inner()
            .into_iter()
            .find(|doc| doc.doc_type == "org.iso.18013.5.1.mDL")
            .ok_or(IsomdlError::DocumentTypeError)?;

        let issuer_signed = document.issuer_signed.clone();

        let mso_bytes = issuer_signed
            .issuer_auth
            .payload()
            .expect("expected a COSE_Sign1 with attached payload, found detached payload");
        let mso: Tag24<Mso> =
            serde_cbor::from_slice(mso_bytes).expect("unable to parse payload as Mso");

        let header = issuer_signed.issuer_auth.unprotected();
        let Some(_x5chain) = header.get_i(33) else {
            return Err(Openid4vpError::Empty("Missing x5chain header".to_string()))
        };

        // let x5c = x5chain.to_owned();
        // let signer_key = match x5c {
        //     CborValue::Text(t) => {
        //         let x509 = x509_cert::Certificate::from_der(t.as_bytes())?;
        //         let signer_key = x509.tbs_certificate.subject_public_key_info.subject_public_key;
        //         signer_key
        //         // to do validate root cert

        //     },
        //     CborValue::Array(a) => {
        //         let leaf = a.first().clone();
        //         if let Some(l) = leaf {
        //             match l {
        //                 CborValue::Text(t) => {
                            
        //                     let x509 = x509_cert::Certificate::from_der(t.as_bytes())?;
        //                     let signer_key = x509.tbs_certificate.subject_public_key_info.subject_public_key;
        //                     signer_key
        //                 },
        //                 _ => { return Err(IsomdlError::CborDecodingError)?}
        //             }
        //         } else {
        //             return Err(IsomdlError::CborDecodingError)?
        //         }

        //         // validate chain to root cert
        //     },
        //     CborValue::Bytes(b) => {
        //         let x509 = x509_cert::Certificate::from_der(&b)?;
        //         let signer_key = x509.tbs_certificate.subject_public_key_info.subject_public_key;
        //         signer_key
        //         // to do validate root cert
        //     }
        //     _ => {
        //         return Err(Openid4vpError::Empty(format!("{:?}", x5c)))?
        //     }

        // };
        // let Some(bytes) = signer_key.as_bytes() else { return Err(Openid4vpError::JoseError("invalid key bytes".to_string()))};
        // let key =VerifyingKey::from_public_key_der(bytes)?;
        
        // parse x509 certificate
        // grab public key from cert
        // validate the chain
        // let issuer_auth = issuer_signed.issuer_auth;
        // let verification_result: cose_rs::sign1::VerificationResult = issuer_auth.verify::<VerifyingKey, Signature>(&key, None, None);
        // if !verification_result.success() {
        //     return Err(IsomdlError::ParsingError)?
        // }

        let device_key = mso.into_inner().device_key_info.device_key;
        let jwk = SsiJwk::try_from(device_key)?;
        let params = jwk.params;
        match params {
            Params::EC(p) => {

                let x_coordinate = p.x_coordinate.clone();
                let y_coordinate = p.y_coordinate.clone();
                let (Some(x), Some(y)) = (x_coordinate, y_coordinate) else {
                    return Err(Openid4vpError::Empty("jwk is missing coordinates".to_string()))
                };
                let encoded_point = p256::EncodedPoint::from_affine_coordinates(
                    GenericArray::from_slice(x.0.as_slice()),
                    GenericArray::from_slice(y.0.as_slice()),
                    false,
                );
                let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)?;

                let namespace_bytes = document.device_signed.namespaces;
                let device_auth = document.device_signed.device_auth;
                match device_auth {
                    DeviceAuth::Signature { device_signature } => {
                        let detached_payload = Tag24::new(UnattendedDeviceAuthentication::new(
                            session_transcript,
                            document.doc_type,
                            namespace_bytes,
                        ))
                        .map_err(|_| IsomdlError::CborDecodingError)?;
                        let external_aad = None;
                        let cbor_payload = serde_cbor::to_vec(&detached_payload)?;
                        let result = device_signature.verify::<VerifyingKey, Signature>(
                            &verifying_key,
                            Some(cbor_payload),
                            external_aad,
                        );
                        if !result.success() {
                            return Err(IsomdlError::ParsingError)?;
                        }
                    }
                    DeviceAuth::Mac { .. } => {
                        // send not yet supported error
                    }
                }
            }
            _ => {}
        }

        let mut parsed_response = BTreeMap::<String, serde_json::Value>::new();
        device_response
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

pub fn decrypted_authorization_response(
    response: String,
    state: UnattendedSessionManager,
) -> Result<(Vec<u8>, Value), Openid4vpError> {
    let decrypter: EcdhEsJweDecrypter<NistP256> =
        josekit::jwe::ECDH_ES.decrypter_from_jwk(&state.esk)?;
    let (payload, _header) = josekit::jwt::decode_with_decrypter(response, &decrypter)?;
    let Some(mdoc_generated_nonce) = _header.claim("apu") else {
        return Err(Openid4vpError::JoseError("missing apu in header".to_string()))
    };

    let vp_token = payload.claim("vp_token");
    if let Some(token) = vp_token {
        match token {
            Value::String(s) => {
                let result = base64url::decode(&s).unwrap();
                Ok((result, mdoc_generated_nonce.to_owned()))
            }
            _ => Err(Openid4vpError::UnrecognizedField),
        }
    } else {
        Err(Openid4vpError::Empty(
            "no vp_token found in the response".to_string(),
        ))
    }
}
