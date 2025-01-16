use crate::traits::{HandshakeStep, HandshakeStream};
use crate::handshake_error::HandshakeError;
use std::collections::VecDeque;

pub struct Handshake {
    protocol_id: String,
    steps: VecDeque<Box<dyn HandshakeStep>>,
}

impl Handshake {
    /// Create a new handshake with an empty list of steps.
    pub fn new(protocol_id: &str) -> Self {
        Self {
            protocol_id: protocol_id.to_string(),
            steps: VecDeque::new(),
        }
    }

    /// Get the protocol ID
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    /// Add a new step to the handshake.
    pub fn add_step(&mut self, mut step: Box<dyn HandshakeStep>) {
        step.set_protocol_id(&self.protocol_id);
        self.steps.push_back(step);
    }

    /// Insert a step at a specific position.
    pub fn insert_step(&mut self, index: usize, step: Box<dyn HandshakeStep>) -> Result<(), HandshakeError> {
        if index <= self.steps.len() {
            self.steps.insert(index, step);
            Ok(())
        } else {
            Err(HandshakeError::Generic(format!(
                "Index {} is out of bounds for inserting a step.",
                index
            )))
        }
    }

    /// Remove a step by index.
    pub fn remove_step(&mut self, index: usize) -> Result<(), HandshakeError> {
        if index < self.steps.len() {
            self.steps.remove(index);
            Ok(())
        } else {
            Err(HandshakeError::Generic(format!(
                "Index {} is out of bounds for removing a step.",
                index
            )))
        }
    }

    /// Replace a step at a specific index.
    pub fn update_step(&mut self, index: usize, step: Box<dyn HandshakeStep>) -> Result<(), HandshakeError> {
        if index < self.steps.len() {
            self.steps[index] = step;
            Ok(())
        } else {
            Err(HandshakeError::Generic(format!(
                "Index {} is out of bounds for updating a step.",
                index
            )))
        }
    }

    /// Retrieve a reference to the current steps.
    pub fn list_steps(&self) -> Vec<&dyn HandshakeStep> {
        self.steps.iter().map(|step| step.as_ref()).collect()
    }

    /// **Execute** the handshake.  Returns the final `Vec<u8>` from the last step.
    pub async fn execute(
        &mut self,
        stream: &mut dyn HandshakeStream,
    ) -> Result<Vec<u8>, HandshakeError> {
        let mut input = Vec::new();
        for step in &mut self.steps {
            if step.supports_protocol(&self.protocol_id) {
                // Each step returns a new Vec<u8>
                input = step.execute(stream, input).await?;
            } else {
                eprintln!(
                    "Skipping step due to protocol mismatch: Expected '{}', Found '{}'",
                    self.protocol_id,
                    step.get_protocol_id()
                );
            }
        }
        // Return the final data from the handshake
        Ok(input)
    }
}
