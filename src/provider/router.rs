//! Provider routing
//!
//! Implements prefix-based routing to select the best provider for a destination.

use super::config::{ProviderConfig, ProviderStats};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Provider router for selecting providers based on destination
pub struct ProviderRouter {
    /// Registered providers
    providers: RwLock<HashMap<String, ProviderConfig>>,
    /// Provider statistics
    stats: RwLock<HashMap<String, ProviderStats>>,
}

impl Default for ProviderRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRouter {
    /// Create a new provider router
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
            stats: RwLock::new(HashMap::new()),
        }
    }

    /// Add a provider
    pub fn add_provider(&self, config: ProviderConfig) {
        let id = config.id.clone();
        self.providers.write().insert(id.clone(), config);
        self.stats.write().insert(id, ProviderStats::default());
    }

    /// Remove a provider
    pub fn remove_provider(&self, id: &str) -> Option<ProviderConfig> {
        self.stats.write().remove(id);
        self.providers.write().remove(id)
    }

    /// Get a provider by ID
    pub fn get_provider(&self, id: &str) -> Option<ProviderConfig> {
        self.providers.read().get(id).cloned()
    }

    /// Get all providers
    pub fn all_providers(&self) -> Vec<ProviderConfig> {
        self.providers.read().values().cloned().collect()
    }

    /// Route a destination to the best provider
    ///
    /// Routing logic:
    /// 1. Find all providers matching the destination prefix
    /// 2. Sort by prefix length (longer = more specific)
    /// 3. Among same-length prefixes, sort by priority
    /// 4. Check concurrent call limits
    /// 5. Return the best available provider
    pub fn route(&self, destination: &str) -> Option<ProviderConfig> {
        let providers = self.providers.read();
        let stats = self.stats.read();

        let mut matches: Vec<_> = providers
            .values()
            .filter(|p| p.matches(destination))
            .filter(|p| {
                // Check concurrent call limit
                if let Some(max) = p.max_concurrent {
                    if let Some(s) = stats.get(&p.id) {
                        if s.active_calls >= max {
                            return false;
                        }
                    }
                }
                true
            })
            .cloned()
            .collect();

        if matches.is_empty() {
            return None;
        }

        // Sort by match length (descending) then priority (ascending)
        matches.sort_by(|a, b| {
            let a_len = a.match_length(destination);
            let b_len = b.match_length(destination);

            match b_len.cmp(&a_len) {
                std::cmp::Ordering::Equal => a.priority.cmp(&b.priority),
                other => other,
            }
        });

        matches.into_iter().next()
    }

    /// Route with fallback - returns multiple providers in priority order
    pub fn route_with_fallback(&self, destination: &str) -> Vec<ProviderConfig> {
        let providers = self.providers.read();
        let stats = self.stats.read();

        let mut matches: Vec<_> = providers
            .values()
            .filter(|p| p.matches(destination))
            .filter(|p| {
                if let Some(max) = p.max_concurrent {
                    if let Some(s) = stats.get(&p.id) {
                        if s.active_calls >= max {
                            return false;
                        }
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Sort by match length (descending) then priority (ascending)
        matches.sort_by(|a, b| {
            let a_len = a.match_length(destination);
            let b_len = b.match_length(destination);

            match b_len.cmp(&a_len) {
                std::cmp::Ordering::Equal => a.priority.cmp(&b.priority),
                other => other,
            }
        });

        matches
    }

    /// Increment active calls for a provider
    pub fn call_started(&self, provider_id: &str) {
        if let Some(stats) = self.stats.write().get_mut(provider_id) {
            stats.active_calls += 1;
            stats.total_calls += 1;
        }
    }

    /// Decrement active calls for a provider
    pub fn call_ended(&self, provider_id: &str) {
        if let Some(stats) = self.stats.write().get_mut(provider_id) {
            stats.active_calls = stats.active_calls.saturating_sub(1);
        }
    }

    /// Record a failed call
    pub fn call_failed(&self, provider_id: &str, error: &str) {
        if let Some(stats) = self.stats.write().get_mut(provider_id) {
            stats.failed_calls += 1;
            stats.last_error = Some(error.to_string());
        }
    }

    /// Update registration status
    pub fn set_registered(&self, provider_id: &str, registered: bool) {
        if let Some(stats) = self.stats.write().get_mut(provider_id) {
            stats.registered = registered;
        }
    }

    /// Get provider stats
    pub fn get_stats(&self, provider_id: &str) -> Option<ProviderStats> {
        self.stats.read().get(provider_id).cloned()
    }

    /// Get all stats
    pub fn all_stats(&self) -> HashMap<String, ProviderStats> {
        self.stats.read().clone()
    }
}

/// Thread-safe router handle
pub type RouterHandle = Arc<ProviderRouter>;

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_router() -> ProviderRouter {
        let router = ProviderRouter::new();

        // US provider - primary
        router.add_provider(
            ProviderConfig::new("plivo-us", "sip.plivo.com", "u", "p")
                .with_prefixes(vec!["+1".to_string()])
                .with_priority(1),
        );

        // US provider - fallback
        router.add_provider(
            ProviderConfig::new("twilio-us", "sip.twilio.com", "u", "p")
                .with_prefixes(vec!["+1".to_string()])
                .with_priority(2),
        );

        // US SF specific (more specific prefix)
        router.add_provider(
            ProviderConfig::new("local-sf", "sip.local.com", "u", "p")
                .with_prefixes(vec!["+1415".to_string()])
                .with_priority(1),
        );

        // UK provider
        router.add_provider(
            ProviderConfig::new("uk-provider", "sip.uk.com", "u", "p")
                .with_prefixes(vec!["+44".to_string()])
                .with_priority(1),
        );

        // Catch-all
        router.add_provider(
            ProviderConfig::new("default", "sip.default.com", "u", "p")
                .with_priority(10),
        );

        router
    }

    #[test]
    fn test_basic_routing() {
        let router = setup_router();

        // UK number should go to UK provider
        let provider = router.route("+447700900000").unwrap();
        assert_eq!(provider.id, "uk-provider");

        // Generic US number should go to plivo (priority 1)
        let provider = router.route("+12125551234").unwrap();
        assert_eq!(provider.id, "plivo-us");
    }

    #[test]
    fn test_specific_prefix_wins() {
        let router = setup_router();

        // SF number should go to local-sf (more specific prefix)
        let provider = router.route("+14155551234").unwrap();
        assert_eq!(provider.id, "local-sf");
    }

    #[test]
    fn test_catch_all() {
        let router = setup_router();

        // Unknown country code should go to catch-all
        let provider = router.route("+81345678901").unwrap();
        assert_eq!(provider.id, "default");
    }

    #[test]
    fn test_fallback_routing() {
        let router = setup_router();

        let providers = router.route_with_fallback("+12125551234");
        assert_eq!(providers.len(), 3); // plivo-us, twilio-us, default
        assert_eq!(providers[0].id, "plivo-us");
        assert_eq!(providers[1].id, "twilio-us");
        assert_eq!(providers[2].id, "default");
    }

    #[test]
    fn test_concurrent_limit() {
        let router = ProviderRouter::new();

        let mut config = ProviderConfig::new("limited", "sip.test.com", "u", "p");
        config.max_concurrent = Some(2);
        router.add_provider(config);

        // First two calls work
        router.call_started("limited");
        router.call_started("limited");

        assert!(router.route("anything").is_none()); // At limit

        // End a call, should work again
        router.call_ended("limited");
        assert!(router.route("anything").is_some());
    }

    #[test]
    fn test_stats_tracking() {
        let router = ProviderRouter::new();
        router.add_provider(ProviderConfig::new("test", "sip.test.com", "u", "p"));

        router.call_started("test");
        router.call_started("test");
        router.call_failed("test", "Timeout");
        router.call_ended("test");
        router.set_registered("test", true);

        let stats = router.get_stats("test").unwrap();
        assert_eq!(stats.active_calls, 1);
        assert_eq!(stats.total_calls, 2);
        assert_eq!(stats.failed_calls, 1);
        assert!(stats.registered);
        assert_eq!(stats.last_error, Some("Timeout".to_string()));
    }
}
