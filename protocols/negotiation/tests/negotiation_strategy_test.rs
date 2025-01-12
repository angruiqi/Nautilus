#[cfg(test)]
mod client_preferred_tests {
    use negotiation::{Negotiable, NegotiationContext, NegotiationError, negotiate_with_strategy};
    use negotiation::negotiation_strategy::ClientPreferred;

    #[derive(Debug, Clone)]
    struct TestItem {
        name: String,
        priority: u8,
        compatible: bool,
    }

    impl Negotiable for TestItem {
        fn priority(&self) -> u8 {
            self.priority
        }

        fn is_compatible(&self, _other: &Self) -> bool {
            self.compatible
        }

        fn name(&self) -> String {
            self.name.clone()
        }
    }

    struct TestContext {
        items: Vec<TestItem>,
    }

    impl NegotiationContext<TestItem> for TestContext {
        fn supported_items(&self) -> Vec<TestItem> {
            self.items.clone()
        }

        fn context_name(&self) -> String {
            "Client Preferred Test Context".to_string()
        }
    }

    #[test]
    fn test_client_preferred_strategy_basic() {
        let strategy = ClientPreferred;

        let client_context = TestContext {
            items: vec![
                TestItem {
                    name: "Item1".to_string(),
                    priority: 1,
                    compatible: true,
                },
                TestItem {
                    name: "Item2".to_string(),
                    priority: 3,
                    compatible: true,
                },
            ],
        };
        let server_context = TestContext {
            items: vec![
                TestItem {
                    name: "Item3".to_string(),
                    priority: 2,
                    compatible: true,
                },
                TestItem {
                    name: "Item2".to_string(),
                    priority: 3,
                    compatible: true,
                },
            ],
        };

        let result = negotiate_with_strategy(&strategy, &client_context, &server_context).unwrap();
        assert_eq!(result.name(), "Item2");
    }

    #[test]
    fn test_client_preferred_empty_context() {
        let strategy = ClientPreferred;

        let client_context = TestContext { items: vec![] };
        let server_context = TestContext { items: vec![] };

        let result = negotiate_with_strategy(&strategy, &client_context, &server_context);
        assert!(matches!(result, Err(NegotiationError::NoCompatibleItems(_))));
    }

    #[test]
    fn test_client_preferred_all_incompatible() {
        let strategy = ClientPreferred;

        let client_context = TestContext {
            items: vec![TestItem {
                name: "Item1".to_string(),
                priority: 1,
                compatible: false,
            }],
        };
        let server_context = TestContext {
            items: vec![TestItem {
                name: "Item2".to_string(),
                priority: 2,
                compatible: false,
            }],
        };

        let result = negotiate_with_strategy(&strategy, &client_context, &server_context);
        assert!(matches!(result, Err(NegotiationError::NoCompatibleItems(_))));
    }
}

#[cfg(test)]
mod weighted_strategy_tests {
    use negotiation::{Negotiable, NegotiationContext};
    use negotiation::negotiation_strategy::WeightedStrategy;
    use negotiation::NegotiationStrategy;

    #[derive(Debug, Clone)]
    struct TestItem {
        name: String,
        priority: u8,
        compatible: bool,
    }

    impl Negotiable for TestItem {
        fn priority(&self) -> u8 {
            self.priority
        }

        fn is_compatible(&self, _other: &Self) -> bool {
            self.compatible
        }

        fn name(&self) -> String {
            self.name.clone()
        }
    }

    struct TestContext {
        items: Vec<TestItem>,
    }

    impl NegotiationContext<TestItem> for TestContext {
        fn supported_items(&self) -> Vec<TestItem> {
            self.items.clone()
        }

        fn context_name(&self) -> String {
            "Weighted Test Context".to_string()
        }
    }

    #[test]
    fn test_weighted_strategy() {
        let strategy = WeightedStrategy {
            client_weights: vec![("AES256-GCM".to_string(), 10), ("ChaCha20".to_string(), 8)],
            server_weights: vec![("AES256-GCM".to_string(), 7), ("ChaCha20".to_string(), 9)],
        };

        let client_context = TestContext {
            items: vec![
                TestItem {
                    name: "AES256-GCM".to_string(),
                    priority: 1,
                    compatible: true,
                },
                TestItem {
                    name: "ChaCha20".to_string(),
                    priority: 2,
                    compatible: true,
                },
            ],
        };

        let server_context = TestContext {
            items: vec![
                TestItem {
                    name: "AES256-GCM".to_string(),
                    priority: 1,
                    compatible: true,
                },
                TestItem {
                    name: "ChaCha20".to_string(),
                    priority: 2,
                    compatible: true,
                },
            ],
        };

        let result = strategy
            .resolve(&client_context, &server_context)
            .expect("Negotiation failed");

        assert_eq!(result.name(), "ChaCha20");
    }
}
