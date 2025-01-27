// protocols\tls\src\tls_state.rs
#[derive(Default)]
pub struct TlsState {
    handshake_complete: bool,
    session_key: Option<Vec<u8>>,
    negotiated_cipher_suite: Option<Vec<u8>>,
    supported_cipher_suites: Vec<u8>,
}

impl TlsState {
    pub fn set_handshake_complete(&mut self, complete: bool) {
        self.handshake_complete = complete;
    }

    pub fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    pub fn set_session_key(&mut self, key: Vec<u8>) {
        self.session_key = Some(key);
    }

    pub fn session_key(&self) -> &[u8] {
        self.session_key.as_deref().unwrap_or_default()
    }

    pub fn set_negotiated_cipher_suite(&mut self, suite: Vec<u8>) {
        self.negotiated_cipher_suite = Some(suite);
    }

    pub fn negotiated_cipher_suite(&self) -> &[u8] {
        self.negotiated_cipher_suite.as_deref().unwrap_or_default()
    }

    pub fn set_supported_cipher_suites(&mut self, suites: Vec<u8>) {
        self.supported_cipher_suites = suites;
    }

    pub fn supported_cipher_suites(&self) -> &[u8] {
        &self.supported_cipher_suites
    }
}
