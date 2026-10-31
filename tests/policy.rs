use eivro::{
    config::{self, ConnectRequest, Mode},
    policy::{Action, PolicyRule, RoutingProfile, Target},
    storage::Settings,
};
use serde_json::json;

#[test]
fn schema_two_migrates_rules_without_changing_subscriptions_or_preferences() {
    let mut settings:Settings=serde_json::from_value(json!({"schema":2,"bypass":["*.example.test","10.0.0.0/8"],"theme":"light","mode":"tun","accent":[1,2,3]})).unwrap();
    settings.migrate().unwrap();
    assert_eq!(settings.schema, 4);
    assert_eq!(settings.routing_profiles.len(), 1);
    assert_eq!(settings.routing_profiles[0].rules.len(), 2);
    assert_eq!(settings.accent, [1, 2, 3]);
    assert!(settings.reconnect && settings.close_to_tray);
    assert!(!settings.kill_switch && !settings.autoconnect);
    let mut restored: Settings =
        serde_json::from_slice(&serde_json::to_vec(&settings).unwrap()).unwrap();
    restored.migrate().unwrap();
    assert_eq!(restored.routing_profiles, settings.routing_profiles);
}

#[test]
fn bulk_add_is_atomic_deduplicated_and_ordered() {
    let mut p = RoutingProfile::default();
    assert_eq!(
        p.add_addresses("example.test\n*.example.test\n10.2.3.4/24", Action::Direct)
            .unwrap(),
        3
    );
    assert_eq!(p.rules[2].target.value(), "10.2.3.0/24");
    assert_eq!(
        p.add_addresses("example.test example.test", Action::Direct)
            .unwrap(),
        0
    );
    let old = p.clone();
    assert!(
        p.add_addresses("valid.test\nhttps://invalid.test/", Action::Direct)
            .is_err()
    );
    assert_eq!(p, old);
    p.rules.insert(
        0,
        PolicyRule {
            enabled: true,
            target: Target::address("private.example.test").unwrap(),
            action: Action::Proxy,
        },
    );
    assert_eq!(p.matches("private.example.test"), Action::Proxy);
    assert_eq!(p.matches("other.example.test"), Action::Direct);
    p.rules[0].enabled = false;
    assert_eq!(p.matches("private.example.test"), Action::Direct);
    assert!(Target::application("firefox").is_err());
    assert!(Target::application("/usr/bin/../firefox").is_err());
}

#[test]
fn routing_priorities_applications_and_guard_config_are_accepted_by_core() {
    let mut p = RoutingProfile::default();
    p.add_addresses("private.example.test", Action::Proxy)
        .unwrap();
    p.add_addresses("*.example.test", Action::Direct).unwrap();
    p.rules.push(PolicyRule {
        enabled: true,
        target: Target::application("/usr/bin/firefox").unwrap(),
        action: Action::Direct,
    });
    let request = ConnectRequest {
        connections: vec![],
        uri: "ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:443".into(),
        bypass: vec![],
        port: 2080,
        bridge_port: None,
        probe_port: Some(2081),
        policies: p.rules,
        kill_switch: true,
    };
    let config = config::generate(&request, Mode::Tun).unwrap();
    assert_eq!(config["route"]["rules"][0]["inbound"], json!(["probe"]));
    assert_eq!(
        config["route"]["rules"][3]["domain"],
        json!(["private.example.test"])
    );
    assert_eq!(
        config["route"]["rules"][5]["process_path"],
        json!(["/usr/bin/firefox"])
    );
    assert_eq!(config["outbounds"][0]["routing_mark"], eivro::guard::MARK);
    assert_eq!(
        config["dns"]["servers"][0]["routing_mark"],
        eivro::guard::MARK
    );
    assert_eq!(config["log"]["disabled"], true);
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
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
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let mut local = request.clone();
    local.kill_switch = false;
    let config = config::generate(&local, Mode::Local).unwrap();
    assert!(!config.to_string().contains("process_path"));
}
