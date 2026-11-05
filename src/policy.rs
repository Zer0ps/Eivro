//! User-owned routing profiles. Rules are ordered; the first enabled match wins.
use crate::{Result, routing::Rule};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Direct,
    Proxy,
    Connection(u64),
}
impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Self::Direct => "Напрямую",
            Self::Proxy => "Через VPN",
            Self::Connection(_) => "Сетевой выход",
        }
    }
    pub fn outbound(self) -> String {
        match self {
            Self::Direct => "direct".into(),
            Self::Proxy => "proxy".into(),
            Self::Connection(id) => format!("network-{id}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Target {
    Address(String),
    Application(String),
}
impl Target {
    pub fn value(&self) -> &str {
        match self {
            Self::Address(s) | Self::Application(s) => s,
        }
    }
    pub fn address(text: &str) -> Result<Self> {
        Ok(Self::Address(Rule::parse(text)?.canonical()))
    }
    pub fn application(text: &str) -> Result<Self> {
        let path = text.trim();
        if !std::path::Path::new(path).is_absolute()
            || path.len() > 4096
            || path.chars().any(char::is_control)
            || path.split(['/', '\\']).any(|p| p == "..")
            || path.ends_with(['/', '\\'])
        {
            return Err("Укажите полный путь к исполняемому файлу программы.".into());
        }
        #[cfg(windows)]
        let path = path.replace('/', "\\");
        #[cfg(not(windows))]
        let path = path.to_owned();
        Ok(Self::Application(path))
    }
    pub fn matcher(&self) -> Result<Value> {
        match self {
            Self::Address(s) => Ok(Rule::parse(s)?.matcher()),
            Self::Application(s) => {
                Self::application(s)?;
                #[cfg(windows)]
                {
                    // Upstream process_path is case-sensitive. Windows paths are
                    // not; anchor and quote the literal path, never accept regex input.
                    let mut pattern = String::from("(?i)^");
                    for ch in s.replace('/', "\\").chars() {
                        if r"\.^$|?*+()[]{}".contains(ch) {
                            pattern.push('\\');
                        }
                        pattern.push(ch);
                    }
                    pattern.push('$');
                    Ok(json!({"process_path_regex":[pattern]}))
                }
                #[cfg(unix)]
                Ok(json!({"process_path":[s]}))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub enabled: bool,
    pub target: Target,
    pub action: Action,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingProfile {
    pub name: String,
    pub rules: Vec<PolicyRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ru_preset: Option<crate::presets::RuPreset>,
}
impl Default for RoutingProfile {
    fn default() -> Self {
        Self {
            name: "Обычный".into(),
            rules: vec![],
            ru_preset: None,
        }
    }
}
impl RoutingProfile {
    pub fn ru(set: crate::presets::RuSet) -> Self {
        Self {
            name: set.name().into(),
            rules: vec![],
            ru_preset: Some(crate::presets::RuPreset::new(set)),
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty()
            || self.name.chars().count() > 40
            || self.name.chars().any(char::is_control)
        {
            return Err("Название профиля: от 1 до 40 символов.".into());
        }
        validate_rules(&self.rules)?;
        if let Some(preset) = &self.ru_preset {
            preset.validate()?;
        }
        Ok(())
    }
    /// Validate the whole batch before changing the draft.
    pub fn add_addresses(&mut self, text: &str, action: Action) -> Result<usize> {
        let targets: Vec<_> = text
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .map(Target::address)
            .collect::<Result<_>>()?;
        if targets.is_empty() {
            return Err("Введите хотя бы один адрес.".into());
        }
        let mut next = self.clone();
        for target in targets {
            if !next
                .rules
                .iter()
                .any(|r| r.target == target && r.action == action)
            {
                next.rules.push(PolicyRule {
                    enabled: true,
                    target,
                    action,
                });
            }
        }
        next.validate()?;
        let added = next.rules.len() - self.rules.len();
        *self = next;
        Ok(added)
    }
    pub fn matches(&self, address: &str) -> Action {
        self.rules
            .iter()
            .find_map(|r| {
                if !r.enabled {
                    return None;
                }
                if let Target::Address(s) = &r.target
                    && Rule::parse(s).is_ok_and(|r| r.matches(address))
                {
                    return Some(r.action);
                }
                None
            })
            .unwrap_or_else(|| {
                if self.ru_preset.as_ref().is_some_and(|p| p.matches(address)) {
                    Action::Direct
                } else {
                    Action::Proxy
                }
            })
    }
}
pub fn validate_rules(rules: &[PolicyRule]) -> Result<()> {
    if rules.len() > 256 {
        return Err("Максимум 256 правил в профиле.".into());
    }
    for r in rules {
        r.target.matcher()?;
    }
    Ok(())
}

pub fn validate_profiles(profiles: &[RoutingProfile], selected: usize) -> Result<()> {
    if profiles.is_empty() || profiles.len() > 24 || selected >= profiles.len() {
        return Err("Нужен выбранный профиль маршрутизации; максимум 24 профиля.".into());
    }
    let mut names = std::collections::HashSet::new();
    for profile in profiles {
        profile.validate()?;
        if !names.insert(profile.name.trim().to_lowercase()) {
            return Err("Названия профилей должны различаться.".into());
        }
    }
    Ok(())
}
