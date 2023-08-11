use serde::de::{Deserializer, Error};

pub fn x509<'de, D>(d: D) -> Result<openssl::x509::X509, D::Error>
where
    D: Deserializer<'de>,
{
    serde_bytes::deserialize(d)
        .map(openssl::x509::X509::from_der)?
        .map_err(D::Error::custom)
}