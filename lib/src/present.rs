use anyhow::Result;
use serde::{Deserialize, Serialize};
use oidc4vp::{utils::Error, jar::RequestObject};
use oidc4vp::presentation_exchange::DescriptorMap;
use oidc4vp::presentation_exchange::PresentationSubmission;
use isomdl;
use isomdl::definitions::device_request::ItemsRequest;
use isomdl::presentation::device::Documents;
use isomdl::presentation::device::DeviceSession;
use isomdl::presentation::device::PermittedItems;
use isomdl::presentation::device::PreparedDeviceResponse;
use signature::{SignatureEncoding, Signer};
use isomdl::definitions::oid4vp::DeviceResponse;
use oidc4vp::mdl_response::Jarm;
use isomdl::definitions::SessionTranscript;
use isomdl::definitions::helpers::Tag24;
use oidc4vp::presentment::Present;
use anyhow::anyhow;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnattendedSessionManager {
    // Note: session transcript will be needed for non oid4vp part of 18013-7
    pub session_transcript: Tag24<SessionTranscript>,
    pub documents: Documents,
}

impl UnattendedSessionManager {
    pub fn new(session_transcript:  Tag24<SessionTranscript>, documents: Documents) -> Result<Self> {
        Ok(UnattendedSessionManager {session_transcript, documents})
    }
}

impl DeviceSession for UnattendedSessionManager {
    fn documents(&self) -> &Documents {
        &self.documents
    }

    fn session_transcript(&self) -> &Tag24<SessionTranscript> {
        &self.session_transcript
    }
}

impl Present for UnattendedSessionManager {
    fn prepare_mdl_response(&self, request: RequestObject) -> Result<PreparedDeviceResponse, Error>{
        if let Some(pres_def) = request.presentation_definition.clone() {
    
            let input_descriptors = pres_def.input_descriptors;
            let items_request: Vec<ItemsRequest> = input_descriptors.iter().map(|input_descriptors| {
                let item_request = ItemsRequest::try_from(input_descriptors.clone()).unwrap();
                item_request
            }).collect();
    
            //let session_manager = isomdl::presentation::device::oid4vp::SessionManager::new(documents, aud, nonce.unwrap(), CoseKey::try_from(jwk).unwrap(), items_request.clone()).unwrap();
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
        else {
            Err(Error::Empty)
        }
    }
    
}

pub fn complete_mdl_response<S, Sig>(mut prepared_response: PreparedDeviceResponse, signer: S)-> Result<Jarm, Error>
where
S: Signer<Sig>, //+ SignatureAlgorithm,
Sig: SignatureEncoding, {
    //sign the payloads
    while let Some((_, payload)) = prepared_response.get_next_signature_payload() {
        let signature = signer
        .try_sign(payload)
        .map_err(|e| anyhow!("error signing cosesign1: {}", e)).unwrap()
        .to_vec();
        prepared_response.submit_next_signature(signature);
    }
    let oid4vp_response = prepared_response.finalize_oid4vp_response();
    authorization_response(oid4vp_response)
    //ssi::jws::encode_sign(, payload, key)
}

fn authorization_response(device_response: DeviceResponse) -> Result<Jarm, Error>{
    
    let descriptor_map = DescriptorMap {
        id: "mDL".to_string(),
        format: "mso_mdoc".to_string(), //TODO: fix
        path: "$".to_string(),
        path_nested: None
    };

    let presentation_submission = PresentationSubmission {
        id: "mDL-req".to_string(),
        definition_id: "mDL-res".to_string(),
        descriptor_map: vec![descriptor_map]
    };

    //TODO: is  this correct?
    let x = isomdl::definitions::helpers::Tag24::new(&device_response).unwrap();
    let vp_token = base64::encode(&x.inner_bytes);

    let jarm = Jarm {
        vp_token: vp_token,
        presentation_submission
    };
    Ok(jarm)
}

#[cfg(test)]
mod test {

    #[test]
    fn prepare_response_test(){

    }
}