use anyhow::Result;
use async_trait::async_trait;
use cose_rs::CoseSign1;
use isomdl;
use isomdl::definitions::device_request::ItemsRequest;
use isomdl::definitions::device_response::Status;
use isomdl::definitions::device_response::{DocumentError, DocumentErrorCode};
use isomdl::definitions::device_signed::DeviceNamespacesBytes;
use isomdl::definitions::helpers::non_empty_map::NonEmptyMap;
use isomdl::definitions::helpers::non_empty_vec::NonEmptyVec;
use isomdl::definitions::helpers::Tag24;
use isomdl::definitions::issuer_signed::IssuerSignedItemBytes;
use isomdl::definitions::oid4vp::DeviceResponse;
use isomdl::definitions::IssuerSigned;
use isomdl::presentation::device::DeviceSession;
use isomdl::presentation::device::Documents;
use isomdl::presentation::device::PermittedItems;
use isomdl::presentation::device::PreparedDeviceResponse;
use isomdl::presentation::device::PreparedDocument;
use isomdl::presentation::device::RequestedItems;
use josekit::jwk::Jwk;
use oidc4vp::mdl_request::ClientMetadata;
use oidc4vp::mdl_request::MetaData;
use oidc4vp::mdl_request::PresDef;
use oidc4vp::presentation_exchange::DescriptorMap;
use oidc4vp::presentation_exchange::{PresentationDefinition, PresentationSubmission};
use oidc4vp::presentment::Present;
use oidc4vp::{mdl_request::RequestObject, utils::Openid4vpError};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_cbor::to_vec;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;
use std::collections::BTreeMap;
use x509_cert::der::Decode;

use crate::x509::X509;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub request_object: RequestObject,
    pub verifier_epk: Jwk,
    pub mdoc_epk: Jwk,
    pub mdoc_esk: Jwk,
}

impl State {
    pub fn new(
        request_object: RequestObject,
        verifier_epk: Jwk,
        mdoc_epk: Jwk,
        mdoc_esk: Jwk,
    ) -> Result<Self> {
        Ok(State {
            request_object,
            verifier_epk,
            mdoc_epk,
            mdoc_esk,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnattendedSessionManager {
    //tag24 this session_transcript?
    pub session_transcript: UnattendedSessionTranscript,
    pub documents: Documents,
}

impl UnattendedSessionManager {
    pub fn new(
        session_transcript: UnattendedSessionTranscript,
        documents: Documents,
    ) -> Result<Self> {
        Ok(UnattendedSessionManager {
            session_transcript,
            documents,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OID4VPHandover(pub String, pub String, pub String, pub String);

#[derive(Clone, Deserialize, Serialize)]
pub struct UnattendedDeviceAuthentication(
    &'static str,
    pub <UnattendedSessionManager as DeviceSession>::T,
    pub String,
    pub DeviceNamespacesBytes,
);

impl UnattendedDeviceAuthentication {
    pub fn new(
        transcript: UnattendedSessionTranscript,
        doc_type: String,
        namespaces_bytes: DeviceNamespacesBytes,
    ) -> Self {
        Self(
            "DeviceAuthentication",
            transcript,
            doc_type,
            namespaces_bytes,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnattendedSessionTranscript(
    pub Option<Vec<u8>>,
    pub Option<Vec<u8>>,
    pub OID4VPHandover,
);

impl DeviceSession for UnattendedSessionManager {
    type T = UnattendedSessionTranscript;
    fn documents(&self) -> &Documents {
        &self.documents
    }

    fn session_transcript(&self) -> Self::T {
        self.session_transcript.clone()
    }

    fn prepare_response(
        &self,
        requests: &RequestedItems,
        permitted: PermittedItems,
    ) -> PreparedDeviceResponse {
        let mut prepared_documents: Vec<PreparedDocument> = Vec::new();
        let mut document_errors: Vec<DocumentError> = Vec::new();

        for (doc_type, namespaces) in
            isomdl::presentation::device::filter_permitted(requests, permitted).into_iter()
        {
            let document = match self.documents().get(&doc_type) {
                Some(doc) => doc,
                None => {
                    // tracing::error!("holder owns no documents of type {}", doc_type);
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let signature_algorithm = match document
                .mso
                .device_key_info
                .device_key
                .signature_algorithm()
            {
                Some(alg) => alg,
                None => {
                    //tracing::error!(
                    //    "device key for document '{}' cannot perform signing",
                    //    document.id
                    //);
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };

            let mut issuer_namespaces: BTreeMap<String, NonEmptyVec<IssuerSignedItemBytes>> =
                Default::default();
            let mut errors: BTreeMap<String, NonEmptyMap<String, DocumentErrorCode>> =
                Default::default();

            // TODO: Handle special cases, i.e. for `age_over_NN`.
            for (namespace, elements) in namespaces.into_iter() {
                if let Some(issuer_items) = document.namespaces.get(&namespace) {
                    for element_identifier in elements.into_iter() {
                        if let Some(item) = issuer_items.get(&element_identifier) {
                            if let Some(returned_items) = issuer_namespaces.get_mut(&namespace) {
                                returned_items.push(item.clone());
                            } else {
                                let returned_items = NonEmptyVec::new(item.clone());
                                issuer_namespaces.insert(namespace.clone(), returned_items);
                            }
                        } else if let Some(returned_errors) = errors.get_mut(&namespace) {
                            returned_errors
                                .insert(element_identifier, DocumentErrorCode::DataNotReturned);
                        } else {
                            let returned_errors = NonEmptyMap::new(
                                element_identifier,
                                DocumentErrorCode::DataNotReturned,
                            );
                            errors.insert(namespace.clone(), returned_errors);
                        }
                    }
                } else {
                    for element_identifier in elements.into_iter() {
                        if let Some(returned_errors) = errors.get_mut(&namespace) {
                            returned_errors
                                .insert(element_identifier, DocumentErrorCode::DataNotReturned);
                        } else {
                            let returned_errors = NonEmptyMap::new(
                                element_identifier,
                                DocumentErrorCode::DataNotReturned,
                            );
                            errors.insert(namespace.clone(), returned_errors);
                        }
                    }
                }
            }

            let device_namespaces = match Tag24::new(Default::default()) {
                Ok(dp) => dp,
                Err(_e) => {
                    let error: DocumentError =
                        [(doc_type.clone(), DocumentErrorCode::DataNotReturned)]
                            .into_iter()
                            .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let device_auth = UnattendedDeviceAuthentication::new(
                self.session_transcript(),
                doc_type.clone(),
                device_namespaces.clone(),
            );
            let device_auth = match Tag24::new(device_auth) {
                Ok(da) => da,
                Err(_e) => {
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let device_auth_bytes = match serde_cbor::to_vec(&device_auth) {
                Ok(dab) => dab,
                Err(_e) => {
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };
            let prepared_cose_sign1 = match CoseSign1::builder()
                .detached()
                .payload(device_auth_bytes)
                .signature_algorithm(signature_algorithm)
                .prepare()
            {
                Ok(prepared) => prepared,
                Err(_e) => {
                    let error: DocumentError = [(doc_type, DocumentErrorCode::DataNotReturned)]
                        .into_iter()
                        .collect();
                    document_errors.push(error);
                    continue;
                }
            };

            let prepared_document = PreparedDocument {
                id: document.id,
                doc_type,
                issuer_signed: IssuerSigned {
                    namespaces: issuer_namespaces.try_into().ok(),
                    issuer_auth: document.issuer_auth.clone(),
                },
                device_namespaces,
                prepared_cose_sign1,
                errors: errors.try_into().ok(),
            };
            prepared_documents.push(prepared_document);
        }
        PreparedDeviceResponse {
            prepared_documents,
            document_errors: document_errors.try_into().ok(),
            status: Status::OK,
            signed_documents: Vec::new(),
        }
    }
}

#[async_trait]
impl Present for UnattendedSessionManager {
    async fn prepare_mdl_response(
        &self,
        request: RequestObject,
    ) -> Result<PreparedDeviceResponse, oidc4vp::utils::Openid4vpError> {
        let pres_def: PresentationDefinition;
        match request.presentation_definition {
            PresDef::PresentationDefinition {
                presentation_definition,
            } => {
                pres_def = presentation_definition;
            }
            PresDef::PresentationDefintionUri {
                presentation_definition_uri,
            } => {
                let response = reqwest::get(presentation_definition_uri).await.unwrap();
                let presentation_definition: PresentationDefinition =
                    response.json().await.unwrap();
                pres_def = presentation_definition;
            }
        }

        let input_descriptors = pres_def.input_descriptors;
        let items_request: Vec<ItemsRequest> = input_descriptors
            .iter()
            .map(|input_descriptors| {
                
                ItemsRequest::try_from(input_descriptors.clone()).unwrap()
            })
            .collect();
        let permitted_items: PermittedItems = items_request
            .clone()
            .into_iter()
            .map(|req| {
                let namespaces = req
                    .namespaces
                    .into_inner()
                    .into_iter()
                    .map(|(ns, es)| {
                        let ids = es.into_inner().into_keys().collect();
                        (ns, ids)
                    })
                    .collect();
                (req.doc_type, namespaces)
            })
            .collect();

        Ok(self.prepare_response(&items_request, permitted_items))
    }
}

fn _validate_mdl_request(jwt: String) -> Result<RequestObject, Openid4vpError> {
    let (header, payload) = ssi::jws::decode_unverified(&jwt)?;
    let x509_chain = header.x509_certificate_chain;
    let request: RequestObject = serde_json::from_slice(&payload)?;
    let client_id_scheme = request.client_id_scheme;

    if let Some(x5chain) = x509_chain {
        let (leaf, intermediary) = x5chain.split_at(1);
        if let Some(cert) = leaf.first() {
            let x509_bytes = base64::decode(cert).unwrap();
            //let x509_certificate = x509_certificate::X509Certificate::from_der(x509_bytes).unwrap();
            let leaf_cert: X509 = X509(openssl::x509::X509::from_der(&x509_bytes)?);
            let intermediary_certs: Vec<X509> = intermediary
                .iter()
                .map(|item| {
                    let bytes = base64::decode(item).unwrap();
                    X509(openssl::x509::X509::from_der(&bytes).unwrap())
                })
                .collect();

            let _chain = crate::x509::X5Chain {
                leaf: leaf_cert,
                intermediate: intermediary_certs,
            };
            //TODO: look up trusted root and verify against that root
            //let verified = chain.verify(root);

            if let Some(scheme) = client_id_scheme {
                if scheme == *"redirect_uri" {
                    //for redirect_uri, we don't need to verify the jwt signature
                    let _redirect_uri = request.client_id;
                } else if scheme == *"x509_san_dns" {
                    //let leaf_key = leaf_cert.public_key().unwrap();
                    let key_info = x509_cert::Certificate::from_der(&x509_bytes)
                        .map_err(|e| format!("could not parse certificate from DER: {e}"))
                        .unwrap()
                        .tbs_certificate
                        .subject_public_key_info;
                    let _alg = key_info.algorithm;
                    //TODO check algorithm identifier for the curve before parsing as p256 key.
                    let parsed_vk = oidc4vp::mdl_request::x509_public_key(x509_bytes).unwrap();
                    let parsed_vk_bytes = parsed_vk.to_sec1_bytes();
                    let parsed_verifier_key = ssi::jwk::p256_parse(&parsed_vk_bytes)?;
                    let parsed_req: RequestObject =
                        ssi::jwt::decode_verify(&jwt, &parsed_verifier_key)?;

                    return Ok(parsed_req);
                } else {
                    return Err(Openid4vpError::InvalidRequest);
                }
            }
        } else {
            return Err(Openid4vpError::InvalidRequest);
        }
    } else {
        return Err(Openid4vpError::InvalidRequest);
    }

    todo!()
}

//TODO: use an enum for request_uri like client_metadata
async fn _retrieve_mdl_request(request_uri: String) -> Result<State, Openid4vpError> {
    let jwt: String = reqwest::get(request_uri).await?.json().await?;
    //decode and verify the jwt, validate x509 chain
    let request_object = _validate_mdl_request(jwt)?;

    match request_object.client_metadata.clone() {
        MetaData::ClientMetadata { client_metadata } => {
            Ok(initialise_session(request_object, client_metadata)?)
        }
        //Note: using client_metadata_uri is not an option in the latest version of 18013-7 anymore
        MetaData::ClientMetadataUri {
            client_metadata_uri,
        } => {
            let client_metadata: ClientMetadata =
                reqwest::get(client_metadata_uri).await?.json().await?;
            Ok(initialise_session(request_object, client_metadata)?)
        }
    }
}

pub async fn prepare_openid4vp_mdl_response(
    state: State,
    documents: Documents,
) -> Result<Vec<u8>, Openid4vpError> {
    let nonce = state.request_object.nonce.clone();
    let client_id = state.request_object.client_id.clone();
    let response_uri = state.request_object.response_uri.clone();

    if nonce.is_some() && response_uri.is_some() {
        let mdoc_generated_nonce: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        let handover = OID4VPHandover(
            mdoc_generated_nonce,
            client_id,
            response_uri.unwrap(),
            nonce.unwrap(),
        );
        let session_transcript = UnattendedSessionTranscript(None, None, handover);
        //tag 24 the session transcript
        let unattended_session_manager =
            UnattendedSessionManager::new(session_transcript, documents)?;

        let prepared_response = unattended_session_manager
            .prepare_mdl_response(state.request_object.clone())
            .await?;

        let (_, tbs) = prepared_response.get_next_signature_payload().unwrap();

        Ok(tbs.to_vec())
    } else {
        Err(Openid4vpError::InvalidRequest)
    }
}

pub async fn complete_mdl_response(
    mut prepared_response: PreparedDeviceResponse,
    state: State,
    signature: Vec<u8>,
) -> Result<String, Openid4vpError> {
    prepared_response.submit_next_signature(signature);

    let oid4vp_response = prepared_response.finalize_oid4vp_response();
    let jwe = encrypted_authorization_response(oid4vp_response, state)?;

    let mut body = Map::new();
    body.insert(
        "response".to_string(),
        serde_json::Value::String(jwe.clone()),
    );
    //let client = reqwest::Client::new();
    //let response = client.post(state.request_object.response_uri.unwrap()).json(&body).send().await?;
    //Ok(response.text().await?)
    Ok(jwe)
}

fn encrypted_authorization_response(
    device_response: DeviceResponse,
    state: State,
) -> Result<String, Openid4vpError> {
    let descriptor_map = DescriptorMap {
        id: "mDL".to_string(),
        format: "mso_mdoc".to_string(), //TODO: fix
        path: "$".to_string(),
        path_nested: None,
    };

    let presentation_submission = PresentationSubmission {
        id: "mDL-req".to_string(),
        definition_id: "mDL-res".to_string(),
        descriptor_map: vec![descriptor_map],
    };

    //TODO: is this correct?
    let inner_bytes = to_vec(&device_response)?;
    let vp_token = base64url::encode(inner_bytes);

    let mut jwe_header = josekit::jwe::JweHeader::new();
    jwe_header.set_token_type("JWT");
    jwe_header.set_content_encryption("A256GCM");
    jwe_header.set_algorithm("ECDH-ES");
    jwe_header
        .set_claim(
            "apv",
            Some(serde_json::Value::String("SKReader".to_string())),
        )
        .unwrap();
    jwe_header
        .set_claim(
            "apu",
            Some(serde_json::Value::String("SKDevice".to_string())),
        )
        .unwrap(); //mdocGeneratedNonce
    jwe_header
        .set_claim(
            "epk",
            Some(serde_json::Value::Object(state.verifier_epk.clone().into())),
        )
        .unwrap();
    let mut jwe_payload = josekit::jwt::JwtPayload::new();
    jwe_payload
        .set_claim("vp_token", Some(serde_json::Value::String(vp_token)))
        .unwrap();
    jwe_payload
        .set_claim(
            "presentation_submission",
            Some(json!(presentation_submission)),
        )
        .unwrap();
    if let Some(state) = state.request_object.state {
        jwe_payload
            .set_claim("state", Some(serde_json::Value::String(state)))
            .unwrap();
    }
    let encrypter = josekit::jwe::ECDH_ES
        .encrypter_from_jwk(&state.verifier_epk)
        .unwrap();
    let jwe = josekit::jwt::encode_with_encrypter(&jwe_payload, &jwe_header, &encrypter).unwrap();

    Ok(jwe)
}

pub fn initialise_session(
    request_object: RequestObject,
    client_metadata: ClientMetadata,
) -> Result<State, Openid4vpError> {
    let supported_alg = "ECDH-ES".to_string();
    let supported_enc = "A256GCM".to_string();
    let supported_crv = "P-256".to_string();
    // also check kty value
    if client_metadata.authorization_encrypted_response_alg != supported_alg {
        return Err(Openid4vpError::UnsupportedEncryptionAlgorithm);
    };
    if client_metadata.authorization_encrypted_response_enc != supported_enc {
        return Err(Openid4vpError::UnsupportedEncryptionEncoding);
    };
    let verifier_jwks: Option<&Value> = client_metadata.jwks.get("keys");
    if let Some(jwks) = verifier_jwks {
        match jwks {
            Value::Array(keys) => {
                let matched_key = keys.iter().find(|key| {
                    match key {
                        Value::Object(obj) => {
                            let verifier_epk = josekit::jwk::Jwk::from_map(obj.clone()).unwrap(); //todo: fix unwrap
                            let curve = verifier_epk.curve();
                            if let Some(c) = curve {
                                *c == supported_crv
                            } else {
                                false
                            }
                        }
                        _ => false,
                    }
                });

                if let Some(key) = matched_key {
                    match key {
                        Value::Object(k) => {
                            let sk_reader = josekit::jwk::Jwk::from_map(k.clone()).unwrap(); //todo: fix unwrap
                                                                                             //todo: dynamic curve selection
                            let cek_pair = josekit::jwe::ECDH_ES
                                .generate_ec_key_pair(josekit::jwk::alg::ec::EcCurve::P256)
                                .unwrap();
                            let sm = State::new(
                                request_object,
                                sk_reader,
                                cek_pair.to_jwk_public_key(),
                                cek_pair.to_jwk_private_key(),
                            )?;
                            Ok(sm)
                        }
                        _ => Err(Openid4vpError::InvalidRequest),
                    }
                } else {
                    Err(Openid4vpError::UnsupportedEncryptionAlgorithm)
                }
            }
            _ => Err(Openid4vpError::InvalidRequest),
        }
    } else {
        Err(Openid4vpError::InvalidRequest)
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn prepare_response_test() {}
}
