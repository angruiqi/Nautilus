// core\src\traits\connection\middleware_traits.rs

/// Middleware trait that wraps connections
pub trait Middleware<C>: Send + Sync {
  type Wrapped;

  fn wrap_connection(&self, connection: C) -> Self::Wrapped;
}

/// MiddlewareConnection trait that defines basic connection operations
pub trait MiddlewareConnection: Send + Sync {
  fn send(&mut self, data: &[u8]) -> Result<(), String>;
  fn receive(&mut self) -> Result<Vec<u8>, String>;
  fn close(&mut self) -> Result<(), String>;
}

/// MiddlewareStack to manage and compose multiple middleware layers
pub struct MiddlewareStack<C> {
  middlewares: Vec<Box<dyn Middleware<C>>>,
}

impl<C> MiddlewareStack<C> {
  pub fn new() -> Self {
      MiddlewareStack {
          middlewares: Vec::new(),
      }
  }

  pub fn add<M: Middleware<C> + 'static>(&mut self, middleware: M) {
      self.middlewares.push(Box::new(middleware));
  }

  pub fn wrap(&self, connection: C) -> C {
      let mut wrapped = connection;
      for middleware in &self.middlewares {
          wrapped = middleware.wrap_connection(wrapped);
      }
      wrapped
  }
}