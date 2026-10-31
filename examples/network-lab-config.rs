//! Synthetic configuration for tests/network_lab.py; contains no real server keys.
use eivro::{
    config::{self, ConnectRequest, Mode},
    network::{Connection, Dns, Interface},
    policy::{Action, PolicyRule, Target},
};
fn main() {
    let req = ConnectRequest {
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
            id: 1,
            name: "Synthetic work".into(),
            interface: "work0".into(),
            dns: Dns::Manual(vec!["10.50.0.53".parse().unwrap()]),
        }],
    };
    let links = if std::env::args().nth(1).as_deref() == Some("unavailable") {
        vec![]
    } else {
        vec![Interface {
            name: "work0".into(),
            index: 7,
            up: true,
            dns: vec![],
        }]
    };
    println!(
        "{}",
        config::generate_with_network(&req, Mode::Local, &links).unwrap()
    );
}
