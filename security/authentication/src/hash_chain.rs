// security\authentication\src\hash_chain.rs
use sha2::{Digest, Sha256};

pub struct HashChain {
    pub chain: Vec<Vec<u8>>,
}

impl HashChain {
    pub fn new(seed: &[u8], iterations: usize) -> Self {
        let mut chain = vec![seed.to_vec()];
        for _ in 1..iterations {
            let last = chain.last().unwrap();
            let hash = Sha256::digest(last);
            chain.push(hash.to_vec());
        }
        Self { chain }
    }

    pub fn validate(&self, idx: usize, hash: &[u8]) -> bool {
        self.chain.get(idx).map_or(false, |stored| stored == hash)
    }
}
