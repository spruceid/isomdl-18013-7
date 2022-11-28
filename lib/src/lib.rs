use std::fs::File;

use anyhow::{anyhow, Context, Result};
use chrono::{Duration, Utc};
use did_jwk::DIDJWK;
use isomdl::presentation::device::{
    oid4vp::SessionManager, DeviceSession, Documents, PermittedItems, RequestedItems,
};
use oidc4vp::presentation_exchange::VpToken;
use p256::ecdsa::signature::{Signature, Signer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::EnumMap;
use siop::{
    openidconnect::{
        core::CoreResponseMode, Audience, IssuerUrl, StandardClaims, SubjectIdentifier, ToSUrl,
    },
    rp::RequestParameters,
    IdToken, IdTokenAdditionalClaims, IdTokenClaims, PrivateWebKey, SigningAlgorithm,
};
use ssi::{
    did::{DIDMethod, Source, VerificationRelationship},
    did_resolve::{get_verification_methods, DIDResolver, ResolutionInputMetadata},
    jwk::{Algorithm, JWK},
    jws::{decode_jws_parts, split_jws},
    jwt, ldp,
    vc::{Contexts, LinkedDataProofOptions, OneOrMany, Presentation, URI},
};
use url::Url;
use uuid::Uuid;

pub use isomdl;
pub use ssi;

const SCHEME: &str = "mdl-openid4vp";

#[derive(Deserialize)]
struct RedirectUrl {
    request_uri: Url,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RequestClaims {
    vp_token: VpToken,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimFormat {
    MsoMdoc { alg: Vec<Algorithm> },
}

// TODO this has to extend ClientRegistrationRequest I think
#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct RegistrationMetadataAdditional {
    subject_syntax_types_supported: Vec<String>,
    #[serde_as(as = "EnumMap")]
    vp_formats: Vec<ClaimFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logo_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tos_uri: Option<ToSUrl>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Request {
    #[serde(flatten)]
    request_parameters: RequestParameters,
    registration: RegistrationMetadataAdditional,
    claims: RequestClaims, // TODO probably needs to come from openidconnect
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    jti: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseRequestJWT {
    id_token: IdToken,
    vp_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Clone, Default)]
pub struct Wallet {
    client: reqwest::Client,
}

pub enum RedirectType {
    InApp(Url),
    Post {
        request_object: Request,
        requested_items: RequestedItems,
        manager: SessionManager,
    },
}

async fn get_jwk(jwt: String) -> Result<JWK> {
    let (headers, payload, sig) = split_jws(&jwt)?;
    let decoded = decode_jws_parts(headers, payload.as_bytes(), sig)?;
    let key_id = decoded.header.key_id.ok_or_else(|| anyhow!("key_id is missing from jwt header"))?;
    let did = key_id.strip_suffix("#auth-key").unwrap_or(key_id.as_str());
    let b64 = did.strip_prefix("did:jwk:").unwrap_or(did);
    let jwk_bytes = base64::decode_config(&b64, base64::URL_SAFE)?;
    serde_json::from_slice(&jwk_bytes).map_err(Into::into)
    //let vms = get_verification_methods(did, VerificationRelationship::Authentication, &DIDJWK)
    //    .await
    //    .map_err(|e| anyhow!("DID resolution failed: {e}"))?;
    //if let Some((_, vm)) = vms.iter().find(|(_, vm)| vm.public_key_jwk.is_some()) {
    //    let jwk = vm.public_key_jwk.as_ref().unwrap().clone();
    //    // jwk.key_id = jwk.key_id.map(|kid| {
    //    //     // TODO would be better with a DID type
    //    //     format!("{}#{}", sub, kid)
    //    // });
    //    Ok(jwk)
    //} else {
    //    Err(anyhow!("Unable to find a verification method with JWK"))
    //}
}

impl Wallet {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .connection_verbose(true)
                .build()
                .unwrap(),
        }
    }

    pub async fn request(&self, url: &Url) -> Result<RedirectType> {
        if url.scheme() != SCHEME {
            return Err(anyhow!("Invalid scheme"));
        }
        if url.query().is_none() {
            return Err(anyhow!("Missing query params"));
        }
        let redirect_url: RedirectUrl =
            serde_urlencoded::from_str(url.query().unwrap()).context("Invalid query parameters")?;

        let request_jwt = self
            .client
            .get(redirect_url.request_uri)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let verifier_jwk = get_jwk(request_jwt.clone()).await?;
        let request_object: Request =
            jwt::decode_verify(&request_jwt, &verifier_jwk).context("Could not decode JWT")?;
        let uri = request_object.request_parameters.redirect_uri.url();

        let mdoc_documents_fd = File::open("lib/mdoc_documents")?;
        let mdoc_documents: Documents = serde_cbor::from_reader(mdoc_documents_fd)?;
        let manager = SessionManager::new(
            mdoc_documents,
            request_object.request_parameters.client_id.to_string(),
            request_object.request_parameters.nonce.secret().to_string(),
            JWK::generate_secp256k1()?, // jwk.clone(),
            verifier_jwk,
            serde_json::Value::Null,
        )
        .expect("failed to prepare response");
        let requested_items = manager.requested_items();

        if let CoreResponseMode::Extension(ref mode) = request_object.request_parameters.response_mode {
            if mode == "post" {
                return Ok(RedirectType::Post {
                    request_object,
                    requested_items: requested_items.to_vec(),
                    manager,
                });
            }
        }
        return Ok(RedirectType::InApp(uri.clone()));
    }

    pub async fn response(
        &self,
        request_object: &Request,
        manager: &SessionManager,
        requested_items: &RequestedItems,
        permitted_items: PermittedItems,
    ) -> Result<()> {
        let mut jwk = JWK::generate_secp256k1()?;
        let der = include_str!("../device_key.b64");
        let der_bytes = base64::decode(der).unwrap();
        let device_key: p256::ecdsa::SigningKey =
            p256::SecretKey::from_sec1_der(&der_bytes).unwrap().into();
        let did = DIDJWK.generate(&Source::Key(&jwk)).unwrap();
        let kid = DIDJWK
            .resolve(&did, &ResolutionInputMetadata::default())
            .await
            .1
            .unwrap()
            .authentication
            .unwrap()[0]
            .get_id(&did);
        jwk.key_id = Some(kid.clone());

        let mut prepared_response = manager.prepare_response(requested_items, permitted_items);
        while let Some((_, payload)) = prepared_response.get_next_signature_payload() {
            let signature = device_key.sign(payload);
            prepared_response.submit_next_signature(signature.as_bytes().to_vec());
        }
        // let _documents: Vec<String> = prepared_response
        //     .finalize_oid4vp_response()
        //     .iter()
        //     .map(|doc| {
        //         serde_cbor::to_vec(&doc)
        //             .map(|doc| base64::encode_config(&doc, base64::URL_SAFE_NO_PAD))
        //     })
        //     .collect::<Result<_, _>>()
        let _documents: String = serde_cbor::to_vec(&prepared_response.finalize_oid4vp_response())
            .map(|docs| base64::encode_config(&docs, base64::URL_SAFE_NO_PAD))
            .unwrap();

        let vp = Presentation {
            context: Contexts::One(ldp::Context::URI(URI::String(
                "https://www.w3.org/2018/credentials/v1".to_string(),
            ))),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            property_set: Some(
                [("mso_mdoc".to_string(), json!([_documents]))]
                    .iter()
                    .cloned()
                    .collect(),
            ),
            ..Default::default()
        };
        let options = LinkedDataProofOptions {
            checks: None,
            created: None,
            proof_purpose: None,
            ..Default::default()
        };
        let response_request = ResponseRequestJWT {
            id_token: IdToken::new(
                IdTokenClaims::new(
                    IssuerUrl::from_url(
                        Url::parse(&format!("https://self-issued.me/v2/{}", SCHEME)).unwrap(),
                    ),
                    vec![Audience::new(
                        request_object.request_parameters.client_id.to_string(),
                    )],
                    Utc::now() + Duration::seconds(300),
                    Utc::now(),
                    StandardClaims::new(SubjectIdentifier::new(kid)),
                    IdTokenAdditionalClaims {
                        sub_jwk: None,
                        vp_token: None,
                    },
                )
                .set_nonce(Some(request_object.request_parameters.nonce.clone())),
                PrivateWebKey::new(&jwk),
                SigningAlgorithm(jwk.get_algorithm().unwrap()),
            )?,
            vp_token: vp.generate_jwt(Some(&jwk), &options, &DIDJWK).await?,
            state: request_object.state.clone(),
        };
        self.client
            .post(request_object.request_parameters.redirect_uri.url().clone())
            .form(&response_request)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
