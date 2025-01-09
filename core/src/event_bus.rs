use tokio::sync::broadcast;
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct EventBus<T: Clone + Send + Sync + Debug + 'static> {
    sender: broadcast::Sender<T>,
}

impl<T: Clone + Send + Sync + Debug + 'static> EventBus<T> {
    /// Creates a new EventBus with the specified buffer size.
    pub fn new(buffer_size: usize) -> Self {
        let (sender, _) = broadcast::channel(buffer_size);
        Self { sender }
    }

    /// Subscribes to the EventBus, receiving a `Receiver` to listen for events.
    pub fn subscribe(&self) -> broadcast::Receiver<T> {
        self.sender.subscribe()
    }

    /// Publishes an event to all subscribers.
    pub async fn publish(&self, event: T) {
        let _ = self.sender.send(event);
    }
}
