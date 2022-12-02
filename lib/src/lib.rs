use anyhow::{anyhow, Context, Result};
use chrono::{Duration, Utc};
use did_jwk::DIDJWK;
use isomdl::presentation::device::{
    oid4vp::SessionManager, DeviceSession, Documents, PermittedItems, RequestedItems,
};
use oidc4vp::presentation_exchange::VpToken;
use p256::ecdsa::signature::{Signature, Signer};
use serde::{Deserialize, Serialize};
use serde_with::EnumMap;
use siop::{
    openidconnect::{
        core::{CoreResponseMode, CoreResponseType},
        Audience, IssuerUrl, StandardClaims, SubjectIdentifier, ToSUrl,
    },
    rp::RequestParameters,
    IdToken, IdTokenAdditionalClaims, IdTokenClaims, PrivateWebKey, SigningAlgorithm,
};
use ssi::{
    did::{DIDMethod, Source},
    did_resolve::{DIDResolver, ResolutionInputMetadata},
    jwk::{Algorithm, JWK},
    jws::{decode_jws_parts, split_jws},
    jwt,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<IdToken>,
    vp_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Clone, Default)]
pub struct Wallet {
    client: reqwest::Client,
}

pub enum ResponseRedirectType {
    InApp(Url),
    Post,
}

pub struct ResponseParams {
    pub request_object: Request,
    pub requested_items: RequestedItems,
    pub manager: SessionManager,
}

async fn get_jwk(jwt: String) -> Result<JWK> {
    let (headers, payload, sig) = split_jws(&jwt)?;
    let decoded = decode_jws_parts(headers, payload.as_bytes(), sig)?;
    let key_id = decoded
        .header
        .key_id
        .ok_or_else(|| anyhow!("key_id is missing from jwt header"))?;
    let did = key_id.strip_suffix("#auth-key").unwrap_or(key_id.as_str());
    let b64 = did.strip_prefix("did:jwk:").unwrap_or(did);
    let jwk_bytes = base64::decode_config(b64, base64::URL_SAFE)?;
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

    pub async fn request(&self, url: &Url) -> Result<ResponseParams> {
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

        let mdoc_documents: Documents =
            serde_cbor::from_slice(include_bytes!("../mdoc_documents"))?;
        let manager = SessionManager::new(
            mdoc_documents,
            request_object.request_parameters.client_id.to_string(),
            request_object.request_parameters.nonce.secret().to_string(),
            JWK::generate_p256()?, // jwk.clone(),
            verifier_jwk,
            serde_json::Value::Null,
        )
        .expect("failed to prepare response");
        let requested_items = manager.requested_items();

        Ok(ResponseParams {
            request_object,
            requested_items: requested_items.to_vec(),
            manager,
        })
    }

    pub async fn response(
        &self,
        request_object: &Request,
        manager: &SessionManager,
        requested_items: &RequestedItems,
        permitted_items: PermittedItems,
    ) -> Result<ResponseRedirectType> {
        let mut jwk = JWK::generate_p256()?;
        let der = include_str!("../device_key.b64");
        let der_bytes = base64::decode(der).unwrap();
        let device_key: p256::ecdsa::SigningKey =
            p256::SecretKey::from_sec1_der(&der_bytes).unwrap().into();
        println!(
            "{:?} {:?}",
            device_key.verifying_key().to_encoded_point(false).x(),
            device_key.verifying_key().to_encoded_point(false).y()
        );
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
        let _documents: String = serde_cbor::to_vec(&prepared_response.finalize_oid4vp_response())
            .map(|docs| base64::encode_config(&docs, base64::URL_SAFE_NO_PAD))
            .unwrap();

        let id_token = match &request_object.request_parameters.response_type {
            CoreResponseType::IdToken => Some(IdToken::new(
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
            )?),
            CoreResponseType::Extension(e) => match e.as_str() {
                "vp_token" => None,
                t => return Err(anyhow!("Unsupported response_type: {}", t)),
            },
            _ => return Err(anyhow!("Unsupported response_type")),
        };

        let response_request = ResponseRequestJWT {
            id_token,
            vp_token: _documents,
            state: request_object.state.clone(),
        };

        match &request_object.request_parameters.response_mode {
            CoreResponseMode::Extension(mode) => match mode.as_str() {
                "post" => {
                    self.client
                        .post(request_object.request_parameters.redirect_uri.url().clone())
                        .form(&response_request)
                        .send()
                        .await?
                        .error_for_status()?;
                    Ok(ResponseRedirectType::Post)
                }
                m => Err(anyhow!("Unknown response_mode: {}", m)),
            },
            CoreResponseMode::Fragment => {
                let mut url = request_object.request_parameters.redirect_uri.url().clone();
                url.set_fragment(Some(&serde_urlencoded::to_string(&response_request)?));
                Ok(ResponseRedirectType::InApp(url))
            }
            _ => Err(anyhow!("No response_mode")),
        }
    }
}
