use crate::process::{
    check_xray, child_command, core_path, version_check, xray_path, xray_version_check,
};
use crate::{
    Result,
    config::{ConnectRequest, Mode, generate},
    import::{EngineKind, Profile, parse_uri},
};
use std::{io::Write, process::Stdio};
/// One offline core check for the complete imported Xray set, before storing keys.
pub fn validate_profiles(profiles: &[Profile]) -> Result<()> {
    let mut outbounds = Vec::new();
    let mut singbox = Vec::new();
    let mut first_singbox = None;
    for profile in profiles {
        let mut parsed = parse_uri(&profile.uri)?;
        if parsed.engine == EngineKind::Xray {
            parsed.outbound["tag"] = serde_json::json!(format!("endpoint-{}", outbounds.len()));
            outbounds.push(parsed.outbound);
        } else {
            if first_singbox.is_none() {
                first_singbox = Some(profile.uri.clone());
            }
            parsed.outbound["tag"] = serde_json::json!(if singbox.is_empty() {
                "proxy".into()
            } else {
                format!("endpoint-{}", singbox.len())
            });
            singbox.push(parsed.outbound);
        }
    }
    if !outbounds.is_empty() {
        let core = xray_path()?;
        xray_version_check(&core)?;
        let mut config = crate::xray::config(outbounds[0].clone(), 2081);
        config["outbounds"] = serde_json::json!(outbounds);
        check_xray(&core, &config)?;
    }
    if let Some(uri) = first_singbox {
        let core = core_path()?;
        version_check(&core)?;
        let mut config = generate(
            &ConnectRequest {
                ru_preset: None,
                connections: vec![],
                probe_port: None,
                policies: vec![],
                kill_switch: false,
                uri,
                bypass: vec![],
                port: 2080,
                bridge_port: None,
            },
            Mode::Proxy,
        )?;
        singbox.push(serde_json::json!({"type":"direct","tag":"direct"}));
        config["outbounds"] = serde_json::json!(singbox);
        let mut child = child_command(&core)
            .args(["check", "-c", crate::process::CONFIG_INPUT])
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
            return Err("sing-box отклонил параметры подключения. Импорт отменён.".into());
        }
    }
    Ok(())
}
