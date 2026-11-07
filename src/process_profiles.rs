use crate::process::{
    CONFIG_INPUT, check_xray, child_command, core_path, version_check, xray_path,
    xray_version_check,
};
use crate::subscription::UnavailableReason;
use crate::{
    Result,
    config::{ConnectRequest, Mode, generate},
    import::{EngineKind, Profile, parse_uri},
};
use serde_json::{Value, json};
use std::{io::Write, path::Path, process::Stdio};

/// Keep the strict interface for explicit validation of an executable profile set.
pub fn validate_profiles(profiles: &[Profile]) -> Result<()> {
    verify(profiles, false).map(|_| ())
}

/// The normal path runs one configuration check per engine. Only a failed
/// group is subdivided. Indices always refer to the original provider order.
pub(crate) fn rejected_profiles(profiles: &[Profile]) -> Result<Vec<(usize, UnavailableReason)>> {
    verify(profiles, true)
}

fn verify(profiles: &[Profile], isolate: bool) -> Result<Vec<(usize, UnavailableReason)>> {
    let mut xray = Vec::new();
    let mut singbox = Vec::new();
    for (index, profile) in profiles.iter().enumerate() {
        let parsed = parse_uri(&profile.uri)?;
        let group = match parsed.engine {
            EngineKind::Xray => &mut xray,
            EngineKind::SingBox => &mut singbox,
        };
        group.push((index, parsed.outbound));
    }
    let mut rejected = Vec::new();
    for (engine, group) in [(EngineKind::Xray, xray), (EngineKind::SingBox, singbox)] {
        let Some((index, _)) = group.first() else {
            continue;
        };
        let core = match engine {
            EngineKind::Xray => xray_path().and_then(|p| xray_version_check(&p).map(|()| p)),
            EngineKind::SingBox => core_path().and_then(|p| version_check(&p).map(|()| p)),
        };
        let core = match core {
            Ok(path) => path,
            Err(_) if isolate => {
                rejected.extend(
                    group
                        .iter()
                        .map(|(i, _)| (*i, UnavailableReason::MissingCore)),
                );
                continue;
            }
            Err(e) => return Err(e),
        };
        if engine == EngineKind::Xray {
            verify_group(&group, isolate, &mut rejected, &|group| {
                let mut config = crate::xray::config(Value::Null, 2081);
                config["outbounds"] = Value::Array(tagged(group));
                check_xray(&core, &config)
            })?;
            continue;
        }
        let base = generate(
            &ConnectRequest {
                ru_preset: None,
                connections: vec![],
                probe_port: None,
                policies: vec![],
                kill_switch: false,
                uri: profiles[*index].uri.clone(),
                bypass: vec![],
                port: 2080,
                bridge_port: None,
            },
            Mode::Proxy,
        )?;
        verify_group(&group, isolate, &mut rejected, &|group| {
            let mut config = base.clone();
            let mut outbounds = tagged(group);
            outbounds.push(json!({"type":"direct","tag":"direct"}));
            config["outbounds"] = Value::Array(outbounds);
            check_singbox(&core, &config)
        })?;
    }
    Ok(rejected)
}

fn tagged(group: &[(usize, Value)]) -> Vec<Value> {
    group
        .iter()
        .enumerate()
        .map(|(i, (_, value))| {
            let mut outbound = value.clone();
            outbound["tag"] = json!(if i == 0 {
                "proxy".into()
            } else {
                format!("endpoint-{i}")
            });
            outbound
        })
        .collect()
}

fn verify_group(
    group: &[(usize, Value)],
    isolate: bool,
    rejected: &mut Vec<(usize, UnavailableReason)>,
    check: &impl Fn(&[(usize, Value)]) -> Result<()>,
) -> Result<()> {
    match check(group) {
        Ok(()) => Ok(()),
        Err(e) if !isolate => Err(e),
        Err(_) if group.len() == 1 => {
            rejected.push((group[0].0, UnavailableReason::Core));
            Ok(())
        }
        Err(_) => {
            let (left, right) = group.split_at(group.len() / 2);
            verify_group(left, true, rejected, check)?;
            verify_group(right, true, rejected, check)
        }
    }
}

fn check_singbox(core: &Path, config: &Value) -> Result<()> {
    let mut child = child_command(core)
        .args(["check", "-c", CONFIG_INPUT])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|_| "Не удалось проверить sing-box.")?;
    let written = child
        .stdin
        .take()
        .ok_or("Нет канала sing-box.")?
        .write_all(config.to_string().as_bytes());
    let status = child.wait().map_err(|_| "Ошибка проверки sing-box.")?;
    if written.is_err() || !status.success() {
        return Err("sing-box отклонил параметры подключения.".into());
    }
    Ok(())
}
