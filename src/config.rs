use crate::{
    Result,
    import::{EngineKind, parse_uri},
    routing::{Rule, parse_rules},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Proxy,
    Local,
    Tun,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectRequest {
    pub uri: String,
    pub bypass: Vec<String>,
    pub port: u16,
    #[serde(default)]
    pub bridge_port: Option<u16>,
    #[serde(default)]
    pub probe_port: Option<u16>,
    #[serde(default)]
    pub policies: Vec<crate::policy::PolicyRule>,
    #[serde(default)]
    pub kill_switch: bool,
}

pub fn generate(req: &ConnectRequest, mode: Mode) -> Result<Value> {
    if req.kill_switch && mode != Mode::Tun {
        return Err("Защита от обрыва доступна только для TUN.".into());
    }
    if req.port < 1024 {
        return Err("Выберите локальный порт от 1024 до 65535.".into());
    }
    let parsed = parse_uri(&req.uri)?;
    let outbound = if parsed.engine == EngineKind::Xray {
        let port = req
            .bridge_port
            .filter(|p| *p >= 1024 && *p != req.port)
            .ok_or("Для Xray не назначен служебный порт.")?;
        json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":port,"version":"5"})
    } else {
        if req.bridge_port.is_some() {
            return Err("Служебный порт допустим только для Xray.".into());
        }
        parsed.outbound
    };
    let bypass = parse_rules(&req.bypass)?;
    let mut routes = vec![
        json!({"action":"sniff"}),
        json!({"protocol":"dns","action":"hijack-dns"}),
    ];
    if let Some(port) = req.probe_port {
        if port < 1024 || port == req.port || Some(port) == req.bridge_port {
            return Err("Некорректный порт проверки соединения.".into());
        }
        // The health check must exercise the selected server even if a user rule
        // would send its destination directly.
        routes.insert(
            0,
            json!({"inbound":["probe"],"action":"route","outbound":"proxy"}),
        );
    }
    let mut dns_rules = Vec::new();
    crate::policy::validate_rules(&req.policies)?;
    for rule in req.policies.iter().filter(|r| r.enabled) {
        if mode != Mode::Tun && matches!(rule.target, crate::policy::Target::Application(_)) {
            continue;
        }
        let mut route = rule.target.matcher()?;
        route["action"] = json!("route");
        route["outbound"] = json!(rule.action.outbound());
        routes.push(route);
        if let crate::policy::Target::Address(address) = &rule.target
            && !matches!(Rule::parse(address)?, Rule::Network(_))
        {
            let mut dns = rule.target.matcher()?;
            dns["action"] = json!("route");
            dns["server"] = json!(if rule.action == crate::policy::Action::Direct {
                "direct-dns"
            } else {
                "proxy-dns"
            });
            dns_rules.push(dns);
        }
    }
    for rule in bypass {
        let mut route = rule.matcher();
        route["action"] = json!("route");
        route["outbound"] = json!("direct");
        routes.push(route);
        if !matches!(rule, Rule::Network(_)) {
            let mut dns = rule.matcher();
            dns["action"] = json!("route");
            dns["server"] = json!("direct-dns");
            dns_rules.push(dns);
        }
    }
    let mut inbounds =
        vec![json!({"type":"mixed","tag":"local","listen":"127.0.0.1","listen_port":req.port})];
    if let Some(port) = req.probe_port {
        inbounds
            .push(json!({"type":"mixed","tag":"probe","listen":"127.0.0.1","listen_port":port}));
    }
    if mode == Mode::Tun {
        inbounds.push(json!({
            "type":"tun","tag":"tun","interface_name":"velum0",
            "address":["172.31.250.1/30","fdfe:5645:4c55::1/126"],
            "mtu":1500,"auto_route":true,"strict_route":true,
            "dns_mode":"hijack","stack":"system"
        }));
    }
    let mut config = json!({
        "log":{"disabled":true},
        "dns":{
            "servers":[
                {"type":"local","tag":"bootstrap"},
                {"type":"https","tag":"direct-dns","server":"1.1.1.1"},
                {"type":"https","tag":"proxy-dns","server":"1.1.1.1","detour":"proxy"}
            ],
            "rules":dns_rules,"final":"proxy-dns","reverse_mapping":true
        },
        "inbounds":inbounds,
        "outbounds":[outbound,{"type":"direct","tag":"direct"}],
        "route":{"auto_detect_interface":true,"default_domain_resolver":"bootstrap","rules":routes,"final":"proxy"},
        "experimental":{"cache_file":{"enabled":false}}
    });
    if req.kill_switch {
        for outbound in config["outbounds"].as_array_mut().unwrap() {
            outbound["routing_mark"] = json!(crate::guard::MARK);
        }
        config["dns"]["servers"][0] = json!({"type":"https","tag":"bootstrap","server":"1.1.1.1","routing_mark":crate::guard::MARK});
        config["dns"]["servers"][1]["routing_mark"] = json!(crate::guard::MARK);
    }
    Ok(config)
}
