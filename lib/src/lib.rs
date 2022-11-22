use anyhow::{anyhow, Context, Result};
use chrono::{Duration, Utc};
use did_jwk::DIDJWK;
use oidc4vp::presentation_exchange::VpToken;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::EnumMap;
use siop::{
    openidconnect::{Audience, IssuerUrl, StandardClaims, SubjectIdentifier, ToSUrl},
    rp::RequestParameters,
    IdToken, IdTokenAdditionalClaims, IdTokenClaims, PrivateWebKey, SigningAlgorithm,
};
use ssi::{
    did::{DIDMethod, Source},
    did_resolve::{DIDResolver, ResolutionInputMetadata},
    jwk::{Algorithm, JWK},
    jwt, ldp,
    vc::{Contexts, LinkedDataProofOptions, OneOrMany, Presentation, URI},
};
use url::Url;
use uuid::Uuid;

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

pub struct Wallet {
    pub client: reqwest::Client,
}

impl Wallet {
    pub async fn request(&self, url: &Url) -> Result<Request> {
        if url.scheme() != "mdl-openid4vp" {
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
        let request_object: Request =
            jwt::decode_unverified(&request_jwt).context("Could not decode JWT")?;
        Ok(request_object)
    }

    pub async fn response(&self, request_object: Request) -> Result<()> {
        let mut jwk = JWK::generate_secp256k1()?;
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
        let mdoc = "".to_string();
        let vp = Presentation {
            context: Contexts::One(ldp::Context::URI(URI::String(
                "https://www.w3.org/2018/credentials/v1".to_string(),
            ))),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            property_set: Some(
                [("mso_mdoc".to_string(), json!(mdoc))]
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
                        Url::parse("https://self-issued.me/v2/mdl-openid4vp").unwrap(),
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
                ),
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
