use const_oid::AssociatedOid;
use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey,
};
use serde::Deserialize;
use std::collections::VecDeque;
use x509_cert::{
    certificate::{Certificate, TbsCertificateInner},
    der::{referenced::OwnedToRef, Decode},
};

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "VecDeque<X509>")]
pub struct X5Chain {
    pub leaf: X509,
    pub intermediate: Vec<X509>,
}

#[derive(Clone, Debug)]
pub enum Error {
    Parsing(String),
    Verification(String),
}

impl TryFrom<VecDeque<X509>> for X5Chain {
    type Error = &'static str;

    fn try_from(mut v: VecDeque<X509>) -> Result<Self, Self::Error> {
        let leaf = v
            .pop_front()
            .ok_or("expected at least one element in x5chain")?;
        let intermediate = v.into();
        Ok(X5Chain { leaf, intermediate })
    }
}

impl X5Chain {
    /// Verify the chain against a trusted root certificate.
    pub fn verify(&self, root: &X509) -> Result<(), Error> {
        let chain = [
            &[&self.leaf],
            self.intermediate.iter().collect::<Vec<&X509>>().as_slice(),
            &[root],
        ]
        .concat();

        Self::verify_chain(&chain)
    }

    /// Verify the chain where the root is included in the chain.
    pub fn verify_rooted(&self) -> Result<(), Error> {
        let chain = [
            &[&self.leaf],
            self.intermediate.iter().collect::<Vec<&X509>>().as_slice(),
        ]
        .concat();

        Self::verify_chain(&chain)
    }

    fn verify_chain(chain: &[&X509]) -> Result<(), Error> {
        let mut pairs = chain.windows(2);
        while let Some(&[child, parent]) = pairs.next() {
            parent.issued(child)?
        }
        Ok(())
    }

    pub fn leaf(&self) -> &X509 {
        &self.leaf
    }

    pub fn root(&self) -> &X509 {
        self.intermediate.last().unwrap_or(&self.leaf)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct X509(#[serde(deserialize_with = "super::de::x509")] pub openssl::x509::X509);

impl X509 {
    /// Validate that this is the apparent issuer of `child` and verify the
    /// signature of `child` using the public key of this certificate.
    pub fn issued(&self, child: &Self) -> Result<(), Error> {
        match self.0.issued(&child.0) {
            openssl::x509::X509VerifyResult::OK => (),
            err => return Err(err.error_string().to_string()).map_err(Error::Verification),
        }
        child.verify(self)
    }

    fn verify(&self, issuer: &Self) -> Result<(), Error> {
        if self
            .0
            .verify(
                issuer
                    .0
                    .public_key()
                    .map_err(|e| format!("unable to parse public key: {e}"))
                    .map_err(Error::Parsing)?
                    .as_ref(),
            )
            .map_err(|e| format!("error occurred while verifying signature: {e}"))
            .map_err(Error::Parsing)?
        {
            Ok(())
        } else {
            Err(format!("signature verification failed: signature from {:?} could not be verified with the key from {:?}", self.0.subject_name(), issuer.0.subject_name())).map_err(Error::Verification)
        }
    }

    fn rustcrypto_cert(&self) -> Result<Certificate, Error> {
        let der = self
            .0
            .to_der()
            .map_err(|e| format!("could not serialize certificate to DER: {e}"))
            .map_err(Error::Parsing)?;
        Certificate::from_der(&der)
            .map_err(|e| format!("could not parse certificate from DER: {e}"))
            .map_err(Error::Parsing)
    }

    pub fn get_tbs(&self) -> Result<TbsCertificateInner, Error> {
        self.rustcrypto_cert().map(|c| c.tbs_certificate)
    }

    pub fn public_key_bytes(&self) -> Result<Vec<u8>, Error> {
        self.rustcrypto_cert().map(|c| {
            c.tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes()
                .to_vec()
        })
    }

    pub fn public_key<C>(&self) -> Result<PublicKey<C>, Error>
    where
        C: AssociatedOid + CurveArithmetic,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        self.rustcrypto_cert().and_then(|c| {
            c.tbs_certificate
                .subject_public_key_info
                .owned_to_ref()
                .try_into()
                .map_err(|e| format!("could not parse public key from pkcs8 spki: {e}"))
                .map_err(Error::Parsing)
        })
    }

    pub fn rsa_public_key(&self) -> Result<rsa::RsaPublicKey, Error> {
        self.rustcrypto_cert().and_then(|c| {
            c.tbs_certificate
                .subject_public_key_info
                .owned_to_ref()
                .try_into()
                .map_err(|e| format!("could not parse public key from pkcs8 spki: {e}"))
                .map_err(Error::Parsing)
        })
    }
}

impl From<openssl::x509::X509> for X509 {
    fn from(cert: openssl::x509::X509) -> Self {
        Self(cert)
    }
}
