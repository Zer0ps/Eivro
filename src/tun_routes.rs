//! Own only the policy-rule delta of one Linux TUN core. Device routes disappear
//! with the TUN; policy rules survive SIGKILL and need the helper to remove them.
use crate::Result;
use serde_json::{Map, Value};
use std::path::Path;

const FIRST: u64 = 9000;
const LAST: u64 = 9010;
const UNSAFE: &str =
    "Правила маршрутизации TUN изменены или имеют неизвестный формат; чужие правила сохранены.";

#[derive(Clone, Debug, PartialEq)]
struct Rule {
    family: &'static str,
    fields: Map<String, Value>,
}
impl Rule {
    fn reserved(&self) -> bool {
        self.fields["priority"]
            .as_u64()
            .is_some_and(|value| (FIRST..=LAST).contains(&value))
    }

    fn delete_args(&self) -> Result<Vec<String>> {
        const KEYS: &[&str] = &[
            "priority",
            "src",
            "srclen",
            "dst",
            "dstlen",
            "not",
            "iif",
            "table",
            "suppress_prefixlen",
            "dport",
            "dport_mask",
            "goto",
            "nop",
            "protocol",
        ];
        if !self.reserved() || self.fields.keys().any(|key| !KEYS.contains(&key.as_str())) {
            return Err(UNSAFE.into());
        }
        let mut args = vec![
            self.family.into(),
            "rule".into(),
            "del".into(),
            "priority".into(),
            self.fields["priority"].to_string(),
        ];
        if let Some(flag) = self.fields.get("not") {
            if !flag.is_null() {
                return Err(UNSAFE.into());
            }
            args.push("not".into());
        }
        for (field, length, selector) in [("src", "srclen", "from"), ("dst", "dstlen", "to")] {
            let address = match self.fields.get(field) {
                Some(value) => value.as_str().ok_or(UNSAFE)?,
                None if field == "dst" => "all",
                None => return Err(UNSAFE.into()),
            };
            let prefix = self.fields.get(length);
            let address = if address == "all" {
                if prefix.is_some() {
                    return Err(UNSAFE.into());
                }
                "all".to_owned()
            } else {
                let ip = address.parse::<std::net::IpAddr>().map_err(|_| UNSAFE)?;
                if ip.is_ipv4() != (self.family == "-4") {
                    return Err(UNSAFE.into());
                }
                match prefix {
                    Some(value) => {
                        let bits = value
                            .as_u64()
                            .filter(|bits| *bits <= if ip.is_ipv4() { 32 } else { 128 })
                            .ok_or(UNSAFE)?;
                        format!("{ip}/{bits}")
                    }
                    None => ip.to_string(),
                }
            };
            args.extend([selector.into(), address]);
        }
        if let Some(interface) = self.fields.get("iif") {
            let interface = interface
                .as_str()
                .filter(|name| *name == "lo" || *name == crate::platform::TUN_NAME)
                .ok_or(UNSAFE)?;
            args.extend(["iif".into(), interface.into()]);
        }
        match (self.fields.get("dport"), self.fields.get("dport_mask")) {
            (Some(port), mask) => {
                let port = port
                    .as_u64()
                    .filter(|port| *port <= u16::MAX as u64)
                    .ok_or(UNSAFE)?;
                let port = match mask {
                    Some(mask) => {
                        let mask = mask
                            .as_str()
                            .and_then(|mask| mask.strip_prefix("0x"))
                            .and_then(|mask| u16::from_str_radix(mask, 16).ok())
                            .ok_or(UNSAFE)?;
                        format!("{port}/0x{mask:x}")
                    }
                    None => port.to_string(),
                };
                args.extend(["dport".into(), port]);
            }
            (None, Some(_)) => return Err(UNSAFE.into()),
            (None, None) => {}
        }
        let actions = ["table", "goto", "nop"]
            .iter()
            .filter(|key| self.fields.contains_key(**key))
            .count();
        if actions != 1 {
            return Err(UNSAFE.into());
        }
        if let Some(table) = self.fields.get("table") {
            let table = table
                .as_str()
                .filter(|table| matches!(*table, "2022" | "main"))
                .ok_or(UNSAFE)?;
            // A table selector alone does not constrain the kernel's rule action.
            args.extend([
                "type".into(),
                "unicast".into(),
                "table".into(),
                table.into(),
            ]);
        } else if let Some(target) = self.fields.get("goto") {
            let target = target
                .as_u64()
                .filter(|target| *target == LAST)
                .ok_or(UNSAFE)?;
            args.extend(["goto".into(), target.to_string()]);
        } else {
            if !self.fields["nop"].is_null() {
                return Err(UNSAFE.into());
            }
            args.extend(["type".into(), "nop".into()]);
        }
        if let Some(prefix) = self.fields.get("suppress_prefixlen") {
            let prefix = prefix
                .as_u64()
                .filter(|prefix| *prefix <= if self.family == "-4" { 32 } else { 128 })
                .ok_or(UNSAFE)?;
            if !self.fields.contains_key("table") {
                return Err(UNSAFE.into());
            }
            args.extend(["suppress_prefixlength".into(), prefix.to_string()]);
        }
        if let Some(protocol) = self.fields.get("protocol") {
            let protocol = match protocol {
                Value::String(value)
                    if matches!(value.as_str(), "unspec" | "kernel" | "boot" | "static")
                        || value.parse::<u8>().is_ok() =>
                {
                    value.clone()
                }
                Value::Number(value) if value.as_u64().is_some_and(|value| value <= 255) => {
                    value.to_string()
                }
                _ => return Err(UNSAFE.into()),
            };
            args.extend(["protocol".into(), protocol]);
        }
        Ok(args)
    }
}

fn parse(family: &'static str, bytes: &[u8]) -> Result<Vec<Rule>> {
    let rows: Vec<Value> = serde_json::from_slice(bytes).map_err(|_| UNSAFE)?;
    rows.into_iter()
        .map(|row| {
            let mut fields = row.as_object().cloned().ok_or(UNSAFE)?;
            if !fields
                .get("priority")
                .and_then(Value::as_u64)
                .is_some_and(|priority| priority <= u32::MAX as u64)
            {
                return Err(UNSAFE.into());
            }
            // Kernel status flags change when the TUN or a goto target disappears;
            // they are not selectors and cannot be passed to rule deletion.
            for flag in ["iif_detached", "oif_detached", "unresolved"] {
                if let Some(value) = fields.remove(flag)
                    && !value.is_null()
                {
                    return Err(UNSAFE.into());
                }
            }
            Ok(Rule { family, fields })
        })
        .collect()
}

fn program() -> Result<&'static str> {
    ["/usr/sbin/ip", "/usr/bin/ip"]
        .into_iter()
        .find(|path| crate::process::trusted_binary(Path::new(path)))
        .ok_or_else(|| "Для восстановления правил TUN нужен системный iproute2.".into())
}
fn snapshot() -> Result<Vec<Rule>> {
    let program = program()?;
    let mut rules = Vec::new();
    for family in ["-4", "-6"] {
        let bytes = crate::network::bounded_output(program, &[family, "-d", "-j", "rule", "show"])
            .map_err(|_| "Не удалось проверить правила маршрутизации TUN.")?;
        rules.extend(parse(family, &bytes)?);
    }
    Ok(rules)
}

#[derive(Default)]
pub(crate) struct Rules {
    before: Option<Vec<Rule>>,
    owned: Option<Vec<Rule>>,
}
impl Rules {
    pub fn begin(&mut self) -> Result<()> {
        self.cleanup()?;
        self.begin_with(snapshot()?)
    }
    fn begin_with(&mut self, before: Vec<Rule>) -> Result<()> {
        // The pinned core's own shutdown deletes this priority range broadly.
        // Refuse to launch it if that could destroy an existing application's rule.
        if before.iter().any(Rule::reserved) {
            return Err("Приоритеты правил TUN 9000–9010 уже заняты. Существующие правила сохранены; отключите другой TUN перед подключением Eivro.".into());
        }
        self.before = Some(before);
        self.owned = None;
        Ok(())
    }
    pub fn capture(&mut self) -> Result<()> {
        self.capture_with(snapshot()?)
    }
    fn capture_with(&mut self, after: Vec<Rule>) -> Result<()> {
        let before = self.before.as_ref().ok_or(UNSAFE)?;
        self.owned = Some(
            after
                .into_iter()
                .filter(|rule| rule.reserved() && !before.contains(rule))
                .collect(),
        );
        // Save the delta even on validation failure so later cleanup cannot
        // silently forget that the kernel may still hold an unsupported rule.
        for rule in self.owned.as_ref().unwrap() {
            rule.delete_args()?;
        }
        Ok(())
    }
    pub fn cleanup(&mut self) -> Result<()> {
        self.cleanup_with(snapshot, |args| {
            let borrowed = args.iter().map(String::as_str).collect::<Vec<_>>();
            crate::network::bounded_output(program()?, &borrowed)
                .map(|_| ())
                .map_err(|_| {
                    "Не удалось удалить собственные правила TUN; очистку можно повторить.".into()
                })
        })
    }
    fn cleanup_with(
        &mut self,
        mut read: impl FnMut() -> Result<Vec<Rule>>,
        mut delete: impl FnMut(&[String]) -> Result<()>,
    ) -> Result<()> {
        if self.before.is_none() {
            return Ok(());
        }
        // Read after a failed/partial startup too, once its core has stopped.
        if self.owned.is_none() {
            self.capture_with(read()?)?;
        }
        let owned = self.owned.as_ref().unwrap();
        let mut current = read()?;
        loop {
            let mut available = owned.clone();
            let mut active = Vec::new();
            for rule in current.iter().filter(|rule| rule.reserved()) {
                let Some(index) = available.iter().position(|owned| owned == rule) else {
                    return Err(UNSAFE.into());
                };
                available.remove(index);
                active.push(rule);
            }
            if active.is_empty() {
                break;
            }
            // Unsupported rules that the core already removed need no delete.
            // Validate every surviving row before mutating any of this group.
            for rule in &active {
                rule.delete_args()?;
            }
            // Missing selectors are wildcards in Linux rule deletion. There
            // must be no foreign rule in the reserved group, even when all
            // supplied selectors match; invert/goto are not identity keys.
            active.sort_by_key(|rule| std::cmp::Reverse(rule.fields.len()));
            delete(&active[0].delete_args()?)?;
            let next = read()?;
            if next.iter().filter(|rule| rule.reserved()).count() >= active.len() {
                return Err("Удаление правил TUN не подтверждено; очистку можно повторить.".into());
            }
            current = next;
        }
        self.before = None;
        self.owned = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::RefCell;

    fn rows(family: &'static str, value: Value) -> Vec<Rule> {
        parse(family, &serde_json::to_vec(&value).unwrap()).unwrap()
    }
    fn baseline() -> Vec<Rule> {
        rows(
            "-4",
            json!([{"priority":0,"src":"all","table":"local"}, {"priority":32766,"src":"all","table":"main"}, {"priority":42000,"src":"all","table":"123"}]),
        )
    }
    fn session() -> Vec<Rule> {
        let mut rules = rows(
            "-4",
            json!([
                {"priority":9000,"src":"all","dst":"172.31.250.0","dstlen":30,"table":"2022"},
                {"priority":9001,"src":"all","table":"2022","suppress_prefixlen":0},
                {"priority":9002,"not":null,"src":"all","dport":53,"dport_mask":"0xffff","table":"main","suppress_prefixlen":0},
                {"priority":9002,"src":"all","iif":"eivro0","goto":9010},
                {"priority":9003,"not":null,"src":"all","iif":"lo","table":"2022"},
                {"priority":9003,"src":"0.0.0.0","iif":"lo","table":"2022"},
                {"priority":9003,"src":"172.31.250.0","srclen":30,"iif":"lo","table":"2022"},
                {"priority":9001,"src":"all","dst":"198.51.100.9","table":"main"},
                {"priority":9010,"src":"all","nop":null}
            ]),
        );
        rules.extend(rows("-6", json!([
            {"priority":9000,"src":"all","table":"2022","suppress_prefixlen":0},
            {"priority":9001,"not":null,"src":"all","dport":53,"dport_mask":"0xffff","table":"main","suppress_prefixlen":0},
            {"priority":9001,"src":"fdfe:5645:4c55::","srclen":126,"iif":"lo","table":"2022"},
            {"priority":9002,"src":"all","iif":"eivro0","goto":9010},
            {"priority":9002,"src":"::","srclen":1,"iif":"lo","goto":9010},
            {"priority":9002,"src":"8000::","srclen":1,"iif":"lo","goto":9010},
            {"priority":9003,"src":"all","table":"2022"},
            {"priority":9010,"src":"all","nop":null}
        ])));
        rules
    }
    fn remove(current: &RefCell<Vec<Rule>>, args: &[String]) -> Result<()> {
        let index = current
            .borrow()
            .iter()
            .position(|rule| rule.delete_args().is_ok_and(|own| own == args))
            .unwrap();
        current.borrow_mut().remove(index);
        Ok(())
    }
    #[test]
    fn occupied_core_priorities_are_rejected_before_start() {
        let mut rules = Rules::default();
        let mut existing = baseline();
        existing.push(rows("-4", json!([{"priority":9000,"src":"all","table":"99"}])).remove(0));
        assert!(rules.begin_with(existing).is_err());
        assert!(rules.before.is_none());
    }
    #[test]
    fn actual_ipv4_ipv6_rules_are_removed_and_other_priorities_survive() {
        let mut rules = Rules::default();
        rules.begin_with(baseline()).unwrap();
        let current = RefCell::new([baseline(), session()].concat());
        rules.capture_with(current.borrow().clone()).unwrap();
        for rule in current
            .borrow_mut()
            .iter_mut()
            .filter(|rule| rule.fields.get("iif").and_then(Value::as_str) == Some("eivro0"))
        {
            rule.fields.insert("iif_detached".into(), Value::Null);
            *rule = rows(rule.family, json!([rule.fields])).remove(0);
        }
        rules
            .cleanup_with(
                || Ok(current.borrow().clone()),
                |args| remove(&current, args),
            )
            .unwrap();
        assert_eq!(current.into_inner(), baseline());
        assert!(rules.before.is_none());
    }
    #[test]
    fn cleanup_refuses_foreign_rules_and_unknown_selectors() {
        let mut rules = Rules::default();
        rules.begin_with(baseline()).unwrap();
        rules.capture_with(session()).unwrap();
        let mut current = session();
        current[0].fields.insert("fwmark".into(), json!(42));
        assert!(
            rules
                .cleanup_with(
                    || Ok(current.clone()),
                    |_| panic!("must not delete foreign rule")
                )
                .is_err()
        );
        assert!(rules.capture_with(current.clone()).is_err());
        assert!(
            rules
                .cleanup_with(
                    || Ok(current.clone()),
                    |_| panic!("must not delete unknown selector")
                )
                .is_err()
        );
        assert!(rules.before.is_some());
    }
    #[test]
    fn partial_start_and_failed_deletion_keep_retryable_ownership() {
        let mut rules = Rules::default();
        rules.begin_with(baseline()).unwrap();
        let current = RefCell::new([baseline(), session()].concat());
        assert!(
            rules
                .cleanup_with(
                    || Ok(current.borrow().clone()),
                    |_| Err("fixture delete failure".into())
                )
                .is_err()
        );
        assert!(rules.owned.is_some());
        rules
            .cleanup_with(
                || Ok(current.borrow().clone()),
                |args| remove(&current, args),
            )
            .unwrap();
        assert_eq!(current.into_inner(), baseline());
    }
    #[test]
    fn cleanup_can_confirm_an_unsupported_rule_was_already_removed() {
        let mut rules = Rules::default();
        rules.begin_with(baseline()).unwrap();
        let mut unsupported = session();
        unsupported[0].fields.insert("fwmark".into(), json!(42));
        assert!(rules.capture_with(unsupported).is_err());
        rules
            .cleanup_with(|| Ok(baseline()), |_| panic!("nothing remains to delete"))
            .unwrap();
        assert!(rules.before.is_none());
    }
    #[test]
    fn arguments_preserve_inversion_prefixes_masks_and_actions() {
        let rules = session();
        let dns = rules[2].delete_args().unwrap();
        assert!(dns.windows(2).any(|pair| pair == ["dport", "53/0xffff"]));
        assert!(dns.windows(2).any(|pair| pair == ["type", "unicast"]));
        assert!(dns.iter().any(|arg| arg == "not"));
        assert!(
            rules[6]
                .delete_args()
                .unwrap()
                .iter()
                .any(|arg| arg == "172.31.250.0/30")
        );
        assert!(
            rules
                .last()
                .unwrap()
                .delete_args()
                .unwrap()
                .windows(2)
                .any(|pair| pair == ["type", "nop"])
        );
    }
}
