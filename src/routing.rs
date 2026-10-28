use crate::Result;
use serde_json::{Value, json};
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq)]
pub enum Rule {
    Exact(String),
    Subdomains(String),
    Network(String),
}

impl Rule {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim().to_lowercase();
        if input.len() > 255 || input.is_empty() {
            return Err("Введите домен, *.домен или IP/CIDR.".into());
        }
        if let Ok(ip) = input.parse::<IpAddr>() {
            return Ok(Self::Network(format!(
                "{ip}/{}",
                if ip.is_ipv4() { 32 } else { 128 }
            )));
        }
        if let Ok(net) = input.parse::<ipnet::IpNet>() {
            return Ok(Self::Network(net.trunc().to_string()));
        }
        let (wild, domain) = input
            .strip_prefix("*.")
            .map_or((false, input.as_str()), |s| (true, s));
        let domain = url::Host::parse(domain)
            .map_err(|_| "Некорректный домен.")?
            .to_string();
        if domain.len() > 253
            || domain.split('.').any(|part| {
                part.is_empty()
                    || part.len() > 63
                    || part.starts_with('-')
                    || part.ends_with('-')
                    || !part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err("Допустимы домен, *.домен или IP/CIDR; без URL и пути.".into());
        }
        Ok(if wild {
            Self::Subdomains(domain)
        } else {
            Self::Exact(domain)
        })
    }

    pub fn canonical(&self) -> String {
        match self {
            Self::Exact(s) | Self::Network(s) => s.clone(),
            Self::Subdomains(s) => format!("*.{s}"),
        }
    }

    pub fn matcher(&self) -> Value {
        match self {
            Self::Exact(s) => json!({"domain": [s]}),
            // Leading dot deliberately excludes the apex, matching shell-style *.example.com.
            Self::Subdomains(s) => json!({"domain_suffix": [format!(".{s}")]}),
            Self::Network(s) => json!({"ip_cidr": [s]}),
        }
    }

    pub fn matches(&self, input: &str) -> bool {
        let input = input.trim().trim_end_matches('.').to_lowercase();
        let input = url::Host::parse(&input)
            .map(|h| h.to_string())
            .unwrap_or(input);
        match self {
            Self::Exact(s) => input == *s,
            Self::Subdomains(s) => input.ends_with(&format!(".{s}")),
            Self::Network(s) => input
                .parse::<IpAddr>()
                .ok()
                .is_some_and(|ip| s.parse::<ipnet::IpNet>().is_ok_and(|net| net.contains(&ip))),
        }
    }
}

pub fn parse_rules(input: &[String]) -> Result<Vec<Rule>> {
    if input.len() > 256 {
        return Err("Максимум 256 правил.".into());
    }
    input.iter().map(|s| Rule::parse(s)).collect()
}
