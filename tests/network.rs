use eivro::{
    config::{self, ConnectRequest, Mode},
    network::{Connection, Dns, Interface},
    policy::{Action, PolicyRule, Target},
    storage::Settings,
};
use serde_json::json;
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn request() -> ConnectRequest {
    ConnectRequest {
        uri: "ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:443".into(),
        port: 2080,
        probe_port: Some(2081),
        bridge_port: None,
        bypass: vec![],
        kill_switch: false,
        connections: vec![Connection {
            id: 1,
            name: "Работа".into(),
            interface: "work0".into(),
            dns: Dns::Interface,
        }],
        policies: vec![PolicyRule {
            enabled: true,
            target: Target::address("*.company.test").unwrap(),
            action: Action::Connection(1),
        }],
    }
}
fn check(config: &serde_json::Value) {
    let mut child = Command::new("vendor/sing-box")
        .args(["check", "-c", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(config.to_string().as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty() && result.stderr.is_empty());
}

#[test]
fn interface_dns_and_direct_connections_use_the_same_explicit_interface() {
    let req = request();
    let links = [Interface {
        name: "work0".into(),
        index: 7,
        up: true,
        dns: vec!["10.50.0.53".parse().unwrap()],
    }];
    for mode in [Mode::Local, Mode::Proxy, Mode::Tun] {
        let cfg = config::generate_with_network(&req, mode, &links).unwrap();
        assert_eq!(cfg["outbounds"][2]["bind_interface"], "work0");
        assert_eq!(cfg["outbounds"][2]["domain_resolver"], "network-dns-1");
        assert_eq!(cfg["dns"]["servers"][3]["server"], "10.50.0.53");
        assert_eq!(cfg["dns"]["servers"][3]["bind_interface"], "work0");
        assert_eq!(cfg["dns"]["rules"][0]["server"], "network-dns-1");
        assert_eq!(cfg["route"]["rules"][0]["inbound"], json!(["probe"]));
        check(&cfg);
    }
}

#[test]
fn unavailable_interface_or_dns_rejects_both_traffic_and_dns_without_fallback() {
    let req = request();
    for links in [
        vec![],
        vec![Interface {
            name: "work0".into(),
            index: 7,
            up: false,
            dns: vec!["10.50.0.53".parse().unwrap()],
        }],
        vec![Interface {
            name: "work0".into(),
            index: 7,
            up: true,
            dns: vec![],
        }],
    ] {
        let cfg = config::generate_with_network(&req, Mode::Tun, &links).unwrap();
        assert_eq!(cfg["route"]["rules"][3]["action"], "reject");
        assert!(cfg["route"]["rules"][3].get("outbound").is_none());
        assert_eq!(cfg["dns"]["rules"][0]["action"], "reject");
        assert!(cfg["dns"]["rules"][0].get("server").is_none());
        assert_eq!(cfg["outbounds"].as_array().unwrap().len(), 2);
        check(&cfg);
    }
}

#[test]
fn manual_dns_never_falls_back_to_interface_dns_and_invalid_references_are_errors() {
    let mut req = request();
    req.connections[0].dns = Dns::Manual(vec!["10.51.0.53".parse().unwrap()]);
    let cfg = config::generate_with_network(
        &req,
        Mode::Proxy,
        &[Interface {
            name: "work0".into(),
            index: 7,
            up: true,
            dns: vec![],
        }],
    )
    .unwrap();
    assert_eq!(cfg["dns"]["servers"][3]["server"], "10.51.0.53");
    req.connections.clear();
    assert!(config::generate(&req, Mode::Proxy).is_err());
    let mut settings = Settings::default();
    settings.routing_profiles[0].rules = req.policies;
    assert!(settings.validate().is_err());
}

#[test]
fn resolved_snapshot_filters_unusable_or_non_plain_dns_and_keeps_link_scope() {
    let mut links = [
        Interface {
            name: "work0".into(),
            index: 7,
            up: true,
            dns: vec![],
        },
        Interface {
            name: "eth0".into(),
            index: 7,
            up: true,
            dns: vec![],
        },
    ];
    eivro::network::apply_dns(&serde_json::to_vec(&json!([
        {"ifname":"work0","servers":[{"addressString":"10.50.0.53","port":53,"accessible":true},{"addressString":"127.0.0.53"},{"addressString":"172.31.250.2"},{"addressString":"10.50.0.54","port":853},{"addressString":"10.50.0.55","accessible":false}]},
        {"ifname":"eth0","servers":[{"addressString":"192.0.2.53"}]}])).unwrap(),&mut links);
    assert_eq!(
        links[0].dns,
        vec!["10.50.0.53".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(
        links[1].dns,
        vec!["192.0.2.53".parse::<std::net::IpAddr>().unwrap()]
    );
    for name in [
        "lo",
        "eivro0",
        "../etc",
        "--help",
        "work 0",
        "",
        "0123456789012345",
    ] {
        assert!(eivro::network::validate_interface(name).is_err());
    }
}

#[test]
fn old_settings_migrate_without_changing_existing_rules_or_network_preferences() {
    let mut settings:Settings=serde_json::from_value(json!({"schema":3,"mode":"tun","theme":"light","accent":[5,6,7],"routing_profiles":[{"name":"Обычный","rules":[{"enabled":true,"target":{"kind":"address","value":"*.example.test"},"action":"direct"}]}]})).unwrap();
    let old = settings.routing_profiles.clone();
    settings.migrate().unwrap();
    assert_eq!(settings.schema, 4);
    assert_eq!(settings.routing_profiles, old);
    assert!(settings.connections.is_empty());
    assert_eq!(settings.accent, [5, 6, 7]);
    settings.connections = request().connections;
    settings.routing_profiles[0].rules = request().policies;
    settings.validate().unwrap();
    let roundtrip: Settings =
        serde_json::from_slice(&serde_json::to_vec(&settings).unwrap()).unwrap();
    roundtrip.validate().unwrap();
    assert_eq!(
        roundtrip.routing_profiles[0].rules[0].action,
        Action::Connection(1)
    );
}

#[test]
fn kill_switch_cannot_break_the_outer_work_vpn_silently() {
    let mut req = request();
    req.kill_switch = true;
    assert!(
        config::generate(&req, Mode::Tun)
            .unwrap_err()
            .contains("Kill switch")
    );
    let mut settings = Settings {
        kill_switch: true,
        connections: req.connections.clone(),
        ..Default::default()
    };
    settings.routing_profiles[0].rules = req.policies.clone();
    assert!(settings.validate().unwrap_err().contains("Kill switch"));
    settings.kill_switch = false;
    settings.validate().unwrap();
    req.policies[0].enabled = false;
    config::generate(&req, Mode::Tun).unwrap();
}

#[test]
fn schema_three_is_backed_up_privately_before_the_new_format_is_written() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("eivro-schema4-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("settings.json");
    let mut value = serde_json::to_value(Settings::default()).unwrap();
    value["schema"] = json!(3);
    value.as_object_mut().unwrap().remove("connections");
    let before = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, &before).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut settings = eivro::storage::load(&path).unwrap();
    settings.connections = request().connections;
    eivro::storage::save(&path, &settings).unwrap();
    let backup = dir.join("settings-before-1.1.json");
    assert_eq!(std::fs::read(&backup).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    eivro::storage::save(&path, &settings).unwrap();
    assert_eq!(std::fs::read(&backup).unwrap(), before);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn interface_monitor_sleeps_and_stops_without_a_timer() {
    let monitor = eivro::network::Monitor::start(std::sync::Arc::new(|| {})).unwrap();
    let start = std::time::Instant::now();
    drop(monitor);
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}
