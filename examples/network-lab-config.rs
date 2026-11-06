//! Synthetic configuration for tests/network_lab.py; contains no real server keys.
use eivro::{
    config::{self, ConnectRequest, Mode},
    network::{Connection, Dns, Interface},
    policy::{Action, PolicyRule, Target},
};
fn main() {
    let mut req = ConnectRequest {
        ru_preset: None,
        uri: "ss://chacha20-ietf-poly1305:synthetic@192.0.2.9:443".into(),
        port: 12080,
        bridge_port: None,
        probe_port: None,
        bypass: vec![],
        policies: vec![PolicyRule {
            enabled: true,
            target: Target::address("*.company.test").unwrap(),
            action: Action::Connection(1),
        }],
        kill_switch: false,
        connections: vec![Connection {
            #[cfg(target_os = "linux")]
            gateway: None,
            id: 1,
            name: "Synthetic work".into(),
            interface: "work0".into(),
            dns: Dns::Manual(vec!["10.50.0.53".parse().unwrap()]),
        }],
    };
    let links = if std::env::args().any(|arg| arg == "unavailable") {
        vec![]
    } else {
        vec![Interface {
            name: "work0".into(),
            index: 7,
            up: true,
            dns: vec![],
        }]
    };
    let tun = std::env::args().any(|arg| arg == "tun");
    if let Some(set) = std::env::args().find_map(|arg| match arg.as_str() {
        "preset-services" => Some(eivro::presets::RuSet::Services),
        "preset-all" => Some(eivro::presets::RuSet::AllNetworks),
        _ => None,
    }) {
        let mut preset = eivro::presets::RuPreset::new(set);
        preset
            .disabled
            .extend(["0rub.beeline.ru".into(), "5.45.192.0/24".into()]);
        req.ru_preset = Some(preset);
        req.policies.insert(
            0,
            PolicyRule {
                enabled: true,
                target: Target::address("override.2gis.com").unwrap(),
                action: Action::Proxy,
            },
        );
    }
    if std::env::args().any(|arg| arg == "direct") {
        req.policies[0].action = Action::Direct;
    }
    if std::env::args().any(|arg| arg == "cidr") {
        req.policies.insert(
            0,
            PolicyRule {
                enabled: true,
                target: Target::address("198.51.100.99/32").unwrap(),
                action: Action::Proxy,
            },
        );
    }
    if let Some(path) =
        std::env::args().find_map(|arg| arg.strip_prefix("application=").map(str::to_owned))
    {
        if let Some(rule) = req
            .policies
            .iter_mut()
            .find(|rule| rule.target.value() == "198.51.100.99/32")
        {
            rule.action = Action::Direct;
        }
        req.policies.insert(
            0,
            PolicyRule {
                enabled: true,
                target: Target::application(&path).unwrap(),
                action: Action::Proxy,
            },
        );
    }
    let cfg =
        config::generate_with_network(&req, if tun { Mode::Tun } else { Mode::Local }, &links)
            .unwrap();
    #[cfg(target_os = "linux")]
    let cfg = {
        let mut cfg = cfg;
        if tun {
            eivro::domain_dns::configure(&mut cfg, &req).unwrap();
        }
        cfg
    };
    println!("{cfg}");
}
