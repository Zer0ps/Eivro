//! Reviewed offline data. User profiles store only the tier and disabled entries.
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::LazyLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuSet {
    Services,
    AllNetworks,
}
impl RuSet {
    pub const ALL: [Self; 2] = [Self::Services, Self::AllNetworks];
    pub fn name(self) -> &'static str {
        match self {
            Self::Services => "RU-DIRECT · Сервисы",
            Self::AllNetworks => "RU-DIRECT · Все сети",
        }
    }
    pub fn networks(self) -> &'static [Entry] {
        static SERVICES: LazyLock<Vec<Entry>> =
            LazyLock::new(|| networks(include_str!("../assets/rules/ru-direct/services-ip.txt")));
        static ALL: LazyLock<Vec<Entry>> =
            LazyLock::new(|| networks(include_str!("../assets/rules/ru-direct/all-ip.txt")));
        match self {
            Self::Services => &SERVICES,
            Self::AllNetworks => &ALL,
        }
    }
    pub fn entries(self) -> impl Iterator<Item = &'static Entry> {
        domains().iter().chain(self.networks())
    }
}

pub struct Entry {
    pub value: &'static str,
    pub network: Option<ipnet::IpNet>,
}
pub fn domains() -> &'static [Entry] {
    static DOMAINS: LazyLock<Vec<Entry>> = LazyLock::new(|| {
        include_str!("../assets/rules/ru-direct/domains.txt")
            .lines()
            .map(|value| Entry {
                value,
                network: None,
            })
            .collect()
    });
    &DOMAINS
}
fn networks(input: &'static str) -> Vec<Entry> {
    input
        .lines()
        .map(|value| Entry {
            value,
            network: Some(value.parse().expect("validated bundled CIDR")),
        })
        .collect()
}
fn enabled() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuPreset {
    pub set: RuSet,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub disabled: BTreeSet<String>,
}
impl RuPreset {
    pub fn new(set: RuSet) -> Self {
        Self {
            set,
            enabled: true,
            disabled: BTreeSet::new(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.disabled.len() > 16000 {
            return Err("Слишком много исключений встроенного списка.".into());
        }
        // Keep removed upstream entries as harmless exclusions across list updates.
        for value in &self.disabled {
            if value.len() > 253 || value.starts_with("*.") {
                return Err("Некорректная запись встроенного списка.".into());
            }
            if crate::routing::Rule::parse(value)?.canonical() != *value {
                return Err("Неканоническая запись встроенного списка.".into());
            }
        }
        Ok(())
    }
    pub fn domain_matcher(&self) -> Option<Value> {
        if !self.enabled {
            return None;
        }
        let values: Vec<_> = domains()
            .iter()
            .filter(|entry| !self.disabled.contains(entry.value))
            .map(|e| e.value)
            .collect();
        if values.is_empty() {
            return None;
        }
        let excluded: Vec<_> = self
            .disabled
            .iter()
            .filter(|value| !value.contains('/'))
            .collect();
        let matcher = json!({"domain_suffix":values});
        Some(if excluded.is_empty() {
            matcher
        } else {
            json!({"type":"logical","mode":"and","rules":[matcher,{"domain_suffix":excluded,"invert":true}]})
        })
    }
    pub fn has_networks(&self) -> bool {
        self.enabled
            && self
                .set
                .networks()
                .iter()
                .any(|entry| !self.disabled.contains(entry.value))
    }
    pub fn headless_rules(&self) -> Vec<Value> {
        if !self.enabled {
            return vec![];
        }
        let mut rules: Vec<_> = self.domain_matcher().into_iter().collect();
        let networks: Vec<_> = self
            .set
            .networks()
            .iter()
            .filter(|e| !self.disabled.contains(e.value))
            .map(|e| e.value)
            .collect();
        if !networks.is_empty() {
            rules.push(json!({"ip_cidr":networks}));
        }
        if rules.is_empty() || self.disabled.is_empty() {
            return rules;
        }
        let (ips, domains): (Vec<_>, Vec<_>) =
            self.disabled.iter().partition(|value| value.contains('/'));
        let mut excluded = vec![];
        if !ips.is_empty() {
            excluded.push(json!({"ip_cidr":ips}));
        }
        if !domains.is_empty() {
            excluded.push(json!({"domain_suffix":domains}));
        }
        vec![json!({"type":"logical","mode":"and","rules":[
            {"type":"logical","mode":"or","rules":rules},
            {"type":"logical","mode":"or","rules":excluded,"invert":true}
        ]})]
    }
    pub fn matches(&self, address: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let address = address.trim().trim_end_matches('.').to_lowercase();
        if let Ok(ip) = address.parse::<std::net::IpAddr>() {
            if self.disabled.iter().any(|value| {
                value
                    .parse::<ipnet::IpNet>()
                    .is_ok_and(|net| net.contains(&ip))
            }) {
                return false;
            }
            return self.set.networks().iter().any(|e| {
                !self.disabled.contains(e.value) && e.network.is_some_and(|net| net.contains(&ip))
            });
        }
        let Ok(host) = url::Host::parse(&address) else {
            return false;
        };
        let host = host.to_string();
        let mut excluded_suffix = host.as_str();
        loop {
            if self.disabled.contains(excluded_suffix) {
                return false;
            }
            let Some((_, rest)) = excluded_suffix.split_once('.') else {
                break;
            };
            excluded_suffix = rest;
        }
        let mut suffix = host.as_str();
        loop {
            if domains().binary_search_by_key(&suffix, |e| e.value).is_ok()
                && !self.disabled.contains(suffix)
            {
                return true;
            }
            let Some((_, rest)) = suffix.split_once('.') else {
                return false;
            };
            suffix = rest;
        }
    }
}
