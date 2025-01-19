// submarine\src\core\event_bus.rs
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct SubmarineEventBus<T: Clone + Send + Sync + 'static> {
    sender: broadcast::Sender<T>,
}

impl<T: Clone + Send + Sync + 'static> SubmarineEventBus<T> {
    pub fn new(size: usize) -> Self {
        let (sender, _) = broadcast::channel(size);
        Self { sender }
    }

    pub async fn publish(&self, event: T) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<T> {
        self.sender.subscribe()
    }
}