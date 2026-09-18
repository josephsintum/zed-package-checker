//! What a user can change, and nothing more.
//!
//! Read from `initializationOptions` at startup and replaced wholesale on
//! `workspace/didChangeConfiguration`. Every field has a default that is what
//! the server did before this module existed, so an absent or malformed
//! configuration is never worse than no configuration.

use serde::Deserialize;

/// The whole user-facing surface.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Config {
    pub online: Online,

    /// Never touch the network for matching; use the downloaded archives only.
    ///
    /// Distinct from `online.enabled: false`, which still downloads archives.
    /// This is the air-gapped switch: it also means a missing archive stays
    /// missing rather than being fetched.
    pub offline: bool,
}

/// Looking advisories up over the network instead of waiting for a 253 MB
/// archive to land.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Online {
    /// On by default: the first run is when people decide whether a tool works,
    /// and waiting for the archive is the difference between five seconds and
    /// one. Turning it off costs only the first run of a given dependency set.
    pub enabled: bool,

    /// Package names never to send, matched as a prefix against
    /// `ecosystem:name` — `npm:@acme/` or a bare `@acme/` both work.
    ///
    /// An internal package name can reveal a product plan, and osv.dev has no
    /// advisories for it either way, so sending it is pure cost.
    pub exclude: Vec<String>,

    /// How long a cached answer is trusted. Matches the archive's own daily
    /// refresh closely enough that neither is meaningfully staler.
    pub ttl_hours: u64,
}

impl Default for Online {
    fn default() -> Self {
        Online {
            enabled: true,
            exclude: Vec::new(),
            ttl_hours: 12,
        }
    }
}

impl Config {
    /// Parses `initializationOptions`, falling back to defaults.
    ///
    /// A malformed value is a warning rather than a failed handshake: the
    /// server is useful with defaults, and refusing to start over a typo in a
    /// settings file is not a trade worth making.
    pub fn from_options(value: Option<&serde_json::Value>) -> Config {
        let Some(value) = value else {
            return Config::default();
        };
        match serde_json::from_value::<Config>(value.clone()) {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(%error, "ignoring unreadable initializationOptions");
                Config::default()
            }
        }
    }

    /// Whether this package may be sent to osv.dev.
    pub fn may_send(&self, ecosystem: crate::model::Ecosystem, name: &str) -> bool {
        let qualified = format!("{ecosystem}:{name}");
        !self.online.exclude.iter().any(|prefix| {
            qualified.starts_with(prefix.as_str()) || name.starts_with(prefix.as_str())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;

    #[test]
    fn defaults_are_what_the_server_did_before() {
        let config = Config::default();
        assert!(config.online.enabled);
        assert!(!config.offline);
        assert_eq!(config.online.ttl_hours, 12);
        assert!(config.online.exclude.is_empty());
    }

    #[test]
    fn absent_options_are_the_defaults() {
        assert_eq!(Config::from_options(None), Config::default());
    }

    #[test]
    fn a_partial_object_keeps_the_other_defaults() {
        let value = serde_json::json!({ "online": { "enabled": false } });
        let config = Config::from_options(Some(&value));
        assert!(!config.online.enabled);
        // Untouched fields are not reset to zero by naming a sibling.
        assert_eq!(config.online.ttl_hours, 12);
    }

    #[test]
    fn camel_case_is_what_an_editor_sends() {
        let value = serde_json::json!({ "online": { "ttlHours": 24 } });
        assert_eq!(Config::from_options(Some(&value)).online.ttl_hours, 24);
    }

    #[test]
    fn a_malformed_value_falls_back_rather_than_failing() {
        // A string where an object belongs: the handshake must still succeed.
        let value = serde_json::json!({ "online": "yes please" });
        assert_eq!(Config::from_options(Some(&value)), Config::default());
    }

    #[test]
    fn exclude_matches_qualified_and_bare_names() {
        let value =
            serde_json::json!({ "online": { "exclude": ["@acme/", "Go:github.com/acme/"] } });
        let config = Config::from_options(Some(&value));

        assert!(!config.may_send(Ecosystem::Npm, "@acme/widgets"));
        assert!(!config.may_send(Ecosystem::Go, "github.com/acme/tool"));
        // A public package that merely starts similarly is still sent.
        assert!(config.may_send(Ecosystem::Npm, "@acmeproducts/public"));
        assert!(config.may_send(Ecosystem::Npm, "lodash"));
    }

    #[test]
    fn zeds_nested_settings_shape_is_accepted() {
        // Zed sends didChangeConfiguration with the server's settings under its
        // own key; the flat shape is what initializationOptions carries.
        let nested = serde_json::json!({ "package-checker": { "online": { "enabled": false } } });
        let inner = nested.get("package-checker").expect("key");
        assert!(!Config::from_options(Some(inner)).online.enabled);
    }

    #[test]
    fn nothing_is_excluded_by_default() {
        assert!(Config::default().may_send(Ecosystem::Npm, "@anything/at-all"));
    }
}
