use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use crate::config::settings::DnsConfig;
use crate::error::{Error, Result};
use crate::scanner::target::{IpFamily, ResolvedTarget};

#[derive(Clone)]
pub struct Resolver {
    inner: Arc<TokioAsyncResolver>,
    config: DnsConfig,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Resolver {
    pub fn new(config: DnsConfig) -> Result<(Self, Option<crate::error::Warning>)> {
        let mut options = ResolverOpts::default();
        options.timeout = config.timeout;
        options.attempts = 1;

        options.cache_size = 4096;

        let mut warning = None;
        let resolver_config = if config.servers.is_empty() {
            match hickory_resolver::system_conf::read_system_conf() {
                Ok((system_config, system_options)) => {
                    options.timeout = config.timeout;
                    options.attempts = system_options.attempts.min(2);
                    system_config
                }
                Err(err) => {
                    warning = Some(crate::error::Warning::global(
                        "dns.system_config",
                        format!(
                            "could not read the system resolver configuration ({err}); \
                             falling back to the default resolver. Use --dns-server to choose one."
                        ),
                    ));
                    ResolverConfig::default()
                }
            }
        } else {
            let group = NameServerConfigGroup::from_ips_clear(&config.servers, 53, true);
            ResolverConfig::from_parts(None, Vec::new(), group)
        };

        let inner = TokioAsyncResolver::tokio(resolver_config, options);
        Ok((
            Self {
                inner: Arc::new(inner),
                config,
            },
            warning,
        ))
    }

    pub async fn resolve(&self, name: &str, family: IpFamily) -> Result<Vec<IpAddr>> {
        let response = self
            .inner
            .lookup_ip(name)
            .await
            .map_err(|e| Error::dns(name.to_string(), e))?;

        let addresses: Vec<IpAddr> = response.iter().filter(|ip| family.accepts(ip)).collect();

        if addresses.is_empty() {
            return Err(Error::invalid_target(
                name,
                format!("resolved, but to no {family} address"),
            ));
        }
        Ok(addresses)
    }

    pub async fn reverse(&self, address: IpAddr) -> Option<String> {
        if !self.config.reverse_lookup {
            return None;
        }
        let response = self.inner.reverse_lookup(address).await.ok()?;
        response
            .iter()
            .next()
            .map(|name| name.to_utf8().trim_end_matches('.').to_ascii_lowercase())
            .filter(|name| !name.is_empty())
    }

    pub fn reverse_enabled(&self) -> bool {
        self.config.reverse_lookup
    }
}

pub async fn resolve_targets(
    resolver: &Resolver,
    names: &[String],
    family: IpFamily,
) -> (Vec<ResolvedTarget>, Vec<crate::error::Warning>) {
    let mut targets = Vec::new();
    let mut warnings = Vec::new();
    let mut seen: HashMap<IpAddr, ()> = HashMap::new();

    let lookups = names.iter().map(|name| async move {
        let result = resolver.resolve(name, family).await;
        (name.clone(), result)
    });
    let results = futures::future::join_all(lookups).await;

    for (name, result) in results {
        match result {
            Ok(addresses) => {
                for address in addresses {
                    if seen.insert(address, ()).is_none() {
                        targets.push(ResolvedTarget {
                            addr: address,
                            source_hostname: Some(name.clone()),
                        });
                    }
                }
            }
            Err(err) => warnings.push(crate::error::Warning::global(
                "dns.resolve_failed",
                format!("{name} could not be resolved: {err}"),
            )),
        }
    }

    (targets, warnings)
}

pub async fn reverse_with_timeout(
    resolver: &Resolver,
    address: IpAddr,
    timeout: Duration,
) -> Option<String> {
    tokio::time::timeout(timeout, resolver.reverse(address))
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offline_config() -> DnsConfig {
        DnsConfig {
            servers: vec!["192.0.2.1".parse().unwrap()],
            timeout: Duration::from_millis(100),
            ..DnsConfig::default()
        }
    }

    #[tokio::test]
    async fn a_resolver_can_be_built_from_explicit_servers() {
        let (resolver, warning) = Resolver::new(offline_config()).unwrap();
        assert!(warning.is_none(), "explicit servers should not warn");
        assert!(resolver.reverse_enabled());
    }

    #[tokio::test]
    async fn unresolvable_names_produce_warnings_not_failures() {
        let (resolver, _) = Resolver::new(offline_config()).unwrap();
        let names = vec![
            "nothing.invalid".to_string(),
            "also-nothing.invalid".to_string(),
        ];
        let (targets, warnings) = resolve_targets(&resolver, &names, IpFamily::V4).await;

        assert!(targets.is_empty());
        assert_eq!(
            warnings.len(),
            2,
            "each failed name should be reported once"
        );
        assert!(warnings.iter().all(|w| w.code == "dns.resolve_failed"));
        assert!(warnings[0].message.contains("nothing.invalid"));
    }

    #[tokio::test]
    async fn reverse_lookup_can_be_disabled() {
        let (resolver, _) = Resolver::new(DnsConfig {
            reverse_lookup: false,
            ..offline_config()
        })
        .unwrap();
        assert!(!resolver.reverse_enabled());
        assert_eq!(resolver.reverse("127.0.0.1".parse().unwrap()).await, None);
    }

    #[tokio::test]
    async fn reverse_lookup_respects_its_timeout() {
        let (resolver, _) = Resolver::new(offline_config()).unwrap();
        let started = std::time::Instant::now();
        let result = reverse_with_timeout(
            &resolver,
            "192.0.2.99".parse().unwrap(),
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(result, None);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the timeout should bound the wait, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn resolution_deduplicates_addresses_across_names() {
        let (resolver, _) = Resolver::new(offline_config()).unwrap();
        let (targets, _) = resolve_targets(
            &resolver,
            &["a.invalid".into(), "a.invalid".into()],
            IpFamily::V4,
        )
        .await;
        assert!(targets.is_empty());
    }
}
