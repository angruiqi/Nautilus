use identity::{PKITraits, PKIError};
use identity::{RSAkeyPair, DilithiumKeyPair, FalconKeyPair, Ed25519KeyPair};
use crate::IdentityError;
use std::fmt;

#[derive(Clone,Debug)]
pub enum Algorithm {
    RSA,
    Dilithium,
    Falcon,
    Ed25519,
}

pub enum PKI {
    RSA(RSAkeyPair),
    Dilithium(DilithiumKeyPair),
    Falcon(FalconKeyPair),
    Ed25519(Ed25519KeyPair),
}

impl PKI {
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, PKIError> {
        match self {
            PKI::RSA(rsa) => rsa.sign(data),
            PKI::Dilithium(dilithium) => dilithium.sign(data),
            PKI::Falcon(falcon) => falcon.sign(data),
            PKI::Ed25519(ed25519) => ed25519.sign(data),
        }
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, PKIError> {
        match self {
            PKI::RSA(rsa) => rsa.verify(data, signature),
            PKI::Dilithium(dilithium) => dilithium.verify(data, signature),
            PKI::Falcon(falcon) => falcon.verify(data, signature),
            PKI::Ed25519(ed25519) => ed25519.verify(data, signature),
        }
    }

    pub fn public_key_raw_bytes(&self) -> Vec<u8> {
        match self {
            PKI::RSA(rsa) => rsa.get_public_key_raw_bytes(),
            PKI::Dilithium(dilithium) => dilithium.get_public_key_raw_bytes(),
            PKI::Falcon(falcon) => falcon.get_public_key_raw_bytes(),
            PKI::Ed25519(ed25519) => ed25519.get_public_key_raw_bytes(),
        }
    }

    pub fn key_type(&self) -> String {
        match self {
            PKI::RSA(_) => RSAkeyPair::key_type(),
            PKI::Dilithium(_) => DilithiumKeyPair::key_type(),
            PKI::Falcon(_) => FalconKeyPair::key_type(),
            PKI::Ed25519(_) => Ed25519KeyPair::key_type(),
        }
    }
}

pub struct PKIFactory;

impl PKIFactory {
    pub fn create_pki(algorithm: Algorithm) -> Result<PKI, IdentityError> {
        match algorithm {
            Algorithm::RSA => {
                let rsa = RSAkeyPair::generate_key_pair()
                    .map_err(|e| IdentityError::Other(format!("RSA key pair generation failed: {}", e)))?;
                Ok(PKI::RSA(rsa))
            }
            Algorithm::Dilithium => {
                let dilithium = DilithiumKeyPair::generate_key_pair()
                    .map_err(|e| IdentityError::Other(format!("Dilithium key pair generation failed: {}", e)))?;
                Ok(PKI::Dilithium(dilithium))
            }
            Algorithm::Falcon => {
                let falcon = FalconKeyPair::generate_key_pair()
                    .map_err(|e| IdentityError::Other(format!("Falcon key pair generation failed: {}", e)))?;
                Ok(PKI::Falcon(falcon))
            }
            Algorithm::Ed25519 => {
                let ed25519 = Ed25519KeyPair::generate_key_pair()
                    .map_err(|e| IdentityError::Other(format!("Ed25519 key pair generation failed: {}", e)))?;
                Ok(PKI::Ed25519(ed25519))
            }
        }
    }
}


impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algo_name = match self {
            Algorithm::RSA => "RSA",
            Algorithm::Dilithium => "Dilithium",
            Algorithm::Falcon => "Falcon",
            Algorithm::Ed25519 => "Ed25519",
        };
        write!(f, "{}", algo_name)
    }
}