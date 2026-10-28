//! Subscription metadata and refresh policy; no connection history.
use crate::{
    Result,
    import::{self, Profile},
    subscription,
};
use base64::{Engine, engine::general_purpose as b64};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn effective_connection(profile: &Profile) -> Result<(import::EngineKind, serde_json::Value)> {
    let parsed = import::parse_uri(&profile.uri)?;
    Ok((parsed.engine, parsed.outbound))
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Metadata {
    pub title: String,
    pub announcement: String,
    pub support_url: Option<String>,
    pub website_url: Option<String>,
    pub interval_hours: Option<u32>,
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    pub expires: Option<u64>,
}
impl Metadata {
    pub fn apply(&mut self, key: &str, value: &str) {
        match key.trim().to_ascii_lowercase().as_str() {
            "profile-title" => self.title = text(value, 80, false),
            "announce" => self.announcement = text(value, 4096, true),
            "support-url" => self.support_url = safe_link(value),
            "profile-web-page-url" => self.website_url = safe_link(value),
            "profile-update-interval" => {
                self.interval_hours = value.trim().parse().ok().filter(|v| (1..=720).contains(v))
            }
            "subscription-userinfo" => {
                for field in value.split(';') {
                    if let Some((key, value)) = field.trim().split_once('=') {
                        let value = value.trim().parse().ok();
                        match key.trim() {
                            "upload" => self.upload = value,
                            "download" => self.download = value,
                            "total" => self.total = value,
                            "expire" => self.expires = value.filter(|v| *v > 0),
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
    pub fn comments(&mut self, content: &str) {
        for line in content.lines() {
            if let Some((key, value)) = line
                .trim()
                .strip_prefix('#')
                .and_then(|s| s.split_once(':'))
            {
                self.apply(key, value);
            }
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.title.chars().count() > 80
            || self.announcement.chars().count() > 4096
            || self.title.chars().any(char::is_control)
            || self
                .announcement
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
            || self.interval_hours.is_some_and(|n| !(1..=720).contains(&n))
            || [&self.support_url, &self.website_url]
                .into_iter()
                .flatten()
                .any(|s| safe_link(s).as_ref() != Some(s))
        {
            return Err("Некорректная информация подписки.".into());
        }
        Ok(())
    }
}
pub fn decode_base64(s: &str) -> Option<String> {
    decode_base64_bytes(s).and_then(|v| String::from_utf8(v).ok())
}
pub(crate) fn decode_base64_bytes(s: &str) -> Option<Vec<u8>> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    [
        b64::STANDARD,
        b64::STANDARD_NO_PAD,
        b64::URL_SAFE,
        b64::URL_SAFE_NO_PAD,
    ]
    .iter()
    .find_map(|b| b.decode(&compact).ok())
}
fn text(s: &str, limit: usize, multiline: bool) -> String {
    let s = s.trim();
    let decoded = s.strip_prefix("base64:").and_then(decode_base64);
    decoded
        .as_deref()
        .unwrap_or(s)
        .chars()
        .filter(|c| !c.is_control() || multiline && (*c == '\n' || *c == '\t'))
        .take(limit)
        .collect()
}
pub fn safe_link(s: &str) -> Option<String> {
    let u = url::Url::parse(s.trim()).ok()?;
    (u.scheme() == "https"
        && u.host_str().is_some()
        && u.username().is_empty()
        && u.password().is_none()
        && s.len() <= 4096)
        .then(|| u.to_string())
}
pub fn source_url(s: &str) -> Result<String> {
    safe_link(s).ok_or_else(|| "Нужна HTTPS-ссылка без HTTP Basic Auth.".into())
}
#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePolicy {
    Manual,
    #[default]
    Provider,
    EveryHours(u32),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subscription {
    pub id: u64,
    pub name: String,
    pub source: Option<String>,
    pub profiles: Vec<Profile>,
    pub selected: usize,
    pub metadata: Metadata,
    pub update: UpdatePolicy,
    pub refreshed_at: Option<u64>,
}
impl Subscription {
    pub fn interval(&self) -> Option<u64> {
        self.source.as_ref()?;
        match self.update {
            UpdatePolicy::Manual => None,
            UpdatePolicy::Provider => self.metadata.interval_hours,
            UpdatePolicy::EveryHours(n) => Some(n),
        }
        .map(|n| n as u64 * 3600)
    }
    pub fn due_at(&self) -> Option<u64> {
        Some(
            self.refreshed_at
                .unwrap_or(0)
                .saturating_add(self.interval()?),
        )
    }
    pub fn selected_profile(&self) -> Option<&Profile> {
        self.profiles.get(self.selected)
    }
    pub fn replace(&mut self, document: Document, now: u64) {
        // A provider can reorder endpoints or rotate credentials. Preserve identity.
        let old = self.selected_profile();
        let selected = old
            .and_then(|p| document.profiles.iter().position(|n| n.uri == p.uri))
            .or_else(|| {
                let previous = effective_connection(old?).ok()?;
                let mut matches = document.profiles.iter().enumerate().filter(|(_, profile)| {
                    effective_connection(profile).is_ok_and(|connection| connection == previous)
                });
                let index = matches.next()?.0;
                matches.next().is_none().then_some(index)
            })
            .or_else(|| {
                old.and_then(|p| {
                    let hits: Vec<_> = document
                        .profiles
                        .iter()
                        .enumerate()
                        .filter(|(_, n)| n.name == p.name)
                        .collect();
                    (hits.len() == 1).then(|| hits[0].0)
                })
            })
            .unwrap_or(0);
        if !document.metadata.title.is_empty() {
            self.name = document.metadata.title.clone();
        }
        self.profiles = document.profiles;
        self.metadata = document.metadata;
        self.selected = selected;
        self.refreshed_at = Some(now);
    }
}
#[derive(Clone)]
pub struct Document {
    pub name: String,
    pub source: Option<String>,
    pub profiles: Vec<Profile>,
    pub metadata: Metadata,
}
impl Document {
    pub fn into_subscription(self, id: u64) -> Subscription {
        Subscription {
            id,
            name: self.name,
            source: self.source,
            profiles: self.profiles,
            selected: 0,
            metadata: self.metadata,
            update: UpdatePolicy::Provider,
            refreshed_at: Some(now()),
        }
    }
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn read_input(input: &str) -> Result<Document> {
    let input = input.trim();
    let (profiles, metadata, source, fallback) = if input.starts_with("https://") {
        let source = source_url(input)?;
        let response = import::download_document(&source)?;
        let (profiles, mut metadata) = subscription::import_document(&response.body)?;
        for (key, value) in response.headers {
            metadata.apply(&key, &value);
        }
        let name = url::Url::parse(&source)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| "Подписка".into());
        (profiles, metadata, Some(source), name)
    } else if Path::new(input).is_absolute() && !input.contains('\n') {
        let (profiles, metadata) = subscription::import_file_document(Path::new(input))?;
        let name = Path::new(input)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Файл");
        (profiles, metadata, None, text(name, 80, false))
    } else {
        let (profiles, metadata) = subscription::import_document(input.as_bytes())?;
        (profiles, metadata, None, "Вручную".into())
    };
    crate::process::validate_profiles(&profiles)?;
    let name = if metadata.title.is_empty() {
        fallback
    } else {
        metadata.title.clone()
    };
    Ok(Document {
        name,
        source,
        profiles,
        metadata,
    })
}
pub fn date(timestamp: u64) -> String {
    let Ok(seconds) = libc::time_t::try_from(timestamp) else {
        return "—".into();
    };
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    if unsafe { libc::gmtime_r(&seconds, &mut tm) }.is_null() {
        return "—".into();
    }
    format!(
        "{:02}.{:02}.{}",
        tm.tm_mday,
        tm.tm_mon + 1,
        tm.tm_year + 1900
    )
}
