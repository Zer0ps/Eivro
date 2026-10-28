//! A single validated outbound, never an executable provider configuration.
use crate::{
    Result,
    import::{EngineKind, Parsed, Profile},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const VERSION: &str = "26.10.21";
pub const PREFIX: &str = "velum-xray://";

fn fields(v: &Value, names: &[&str], context: &str) -> Result<()> {
    let object = v
        .as_object()
        .ok_or_else(|| format!("{context}: нужен объект."))?;
    let unknown: Vec<_> = object
        .keys()
        .filter(|k| !names.contains(&k.as_str()))
        .collect();
    if !unknown.is_empty() {
        // Field values can contain credentials; errors only identify a schema section.
        return Err(format!("{context}: есть неподдерживаемые поля."));
    }
    Ok(())
}
fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
fn endpoint(v: &Value) -> Result<String> {
    let host = s(v, "address");
    if host.is_empty()
        || host.len() > 253
        || host.chars().any(char::is_control)
        || v.get("port")
            .and_then(Value::as_u64)
            .is_none_or(|p| p == 0 || p > 65535)
    {
        return Err("Xray: неверный адрес или порт сервера.".into());
    }
    Ok(host.into())
}
fn single<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    v.get(key)
        .and_then(Value::as_array)
        .filter(|v| v.len() == 1)
        .map(|v| &v[0])
        .ok_or_else(|| format!("Xray: в {key} нужна одна запись."))
}
fn disabled(v: &Value, key: &str) -> Result<()> {
    if v.get(key).is_some_and(|v| v != false) {
        return Err("Xray: отключение проверки TLS не допускается.".into());
    }
    Ok(())
}

fn validate_xhttp(v: &mut Value) -> Result<()> {
    fields(v, &["path", "host", "mode", "extra"], "XHTTP")?;
    if !["", "auto", "packet-up", "stream-up", "stream-one"].contains(&s(v, "mode")) {
        return Err("XHTTP: неизвестный mode.".into());
    }
    for key in ["path", "host", "mode"] {
        if v.get(key).is_some_and(|v| !v.is_string()) {
            return Err("XHTTP: неверный тип параметра.".into());
        }
    }
    if let Some(extra) = v.get_mut("extra") {
        fields(
            extra,
            &[
                "xPaddingBytes",
                "noSSEHeader",
                "scMaxEachPostBytes",
                "scMinPostsIntervalMs",
                "scMaxBufferedPosts",
                "scStreamUpServerSecs",
                "xmux",
                "uplinkHTTPMethod",
                "sessionPlacement",
                "sessionKey",
                "sessionIDPlacement",
                "sessionIDKey",
                "seqPlacement",
                "seqKey",
                "uplinkDataPlacement",
                "uplinkDataKey",
                "uplinkChunkSize",
                "xPaddingObfsMode",
                "xPaddingHeader",
                "xPaddingKey",
                "xPaddingPlacement",
                "xPaddingMethod",
            ],
            "XHTTP extra",
        )?;
        if let Some(m) = extra.get("xmux") {
            fields(
                m,
                &[
                    "maxConcurrency",
                    "maxConnections",
                    "cMaxReuseTimes",
                    "hMaxRequestTimes",
                    "hMaxReusableSecs",
                    "hKeepAlivePeriod",
                ],
                "XHTTP xmux",
            )?;
        }
        // Xray 26.9.30 renamed these fields and silently ignores the old names.
        // Normalize saved profiles as well as new imports before core validation.
        let extra = extra.as_object_mut().ok_or("XHTTP extra: нужен объект.")?;
        for (old, new) in [
            ("sessionPlacement", "sessionIDPlacement"),
            ("sessionKey", "sessionIDKey"),
        ] {
            if let Some(value) = extra.remove(old) {
                if extra.get(new).is_some_and(|current| *current != value) {
                    return Err(
                        "XHTTP extra: старые и новые параметры сессии противоречат друг другу."
                            .into(),
                    );
                }
                extra.insert(new.into(), value);
            }
        }
    }
    Ok(())
}

pub fn parse_outbound(input: &Value) -> Result<Parsed> {
    if serde_json::to_vec(input)
        .map_err(|_| "Некорректный Xray JSON.")?
        .len()
        > 48 * 1024
    {
        return Err("Профиль Xray слишком большой.".into());
    }
    fields(
        input,
        &["protocol", "tag", "settings", "streamSettings", "mux"],
        "Xray outbound",
    )?;
    let protocol = s(input, "protocol");
    if !["vless", "vmess", "trojan", "shadowsocks", "hysteria"].contains(&protocol) {
        return Err("Xray: этот протокол подключения пока не поддерживается.".into());
    }
    let settings = input.get("settings").ok_or("Xray: нет settings.")?;
    let host;
    if ["vless", "vmess"].contains(&protocol) {
        fields(settings, &["vnext"], "Xray settings")?;
        let server = single(settings, "vnext")?;
        fields(server, &["address", "port", "users"], "Xray server")?;
        host = endpoint(server)?;
        let user = single(server, "users")?;
        fields(
            user,
            &[
                "id",
                "encryption",
                "flow",
                "security",
                "alterId",
                "level",
                "email",
            ],
            "Xray user",
        )?;
        crate::import::validate_uuid(s(user, "id"))?;
        if protocol == "vless" {
            if !["", "none"].contains(&s(user, "encryption")) {
                return Err("Неподдерживаемое VLESS encryption.".into());
            }
            if !["", "xtls-rprx-vision"].contains(&s(user, "flow")) {
                return Err("Неподдерживаемый VLESS flow.".into());
            }
        } else if user.get("alterId").is_some_and(|v| v != 0) {
            return Err("Нужен VMess AEAD (alterId=0).".into());
        }
    } else if protocol == "hysteria" {
        fields(settings, &["address", "port", "version"], "Xray Hysteria")?;
        if settings.get("version") != Some(&json!(2)) {
            return Err("Поддерживается Hysteria версии 2.".into());
        }
        host = endpoint(settings)?;
    } else {
        fields(settings, &["servers"], "Xray settings")?;
        let server = single(settings, "servers")?;
        fields(
            server,
            &[
                "address",
                "port",
                "password",
                "method",
                "level",
                "email",
                "ota",
                "uot",
                "UoTVersion",
            ],
            "Xray server",
        )?;
        host = endpoint(server)?;
        if s(server, "password").is_empty() {
            return Err("Xray: нет пароля.".into());
        }
        if server.get("ota").is_some_and(|v| v != false) {
            return Err("Legacy Shadowsocks OTA не поддерживается.".into());
        }
        if protocol == "shadowsocks"
            && ![
                "aes-128-gcm",
                "aes-256-gcm",
                "chacha20-ietf-poly1305",
                "2022-blake3-aes-128-gcm",
                "2022-blake3-aes-256-gcm",
                "2022-blake3-chacha20-poly1305",
            ]
            .contains(&s(server, "method"))
        {
            return Err("Нужен AEAD-метод Shadowsocks.".into());
        }
    }
    let mut out = input.clone();
    if let Some(m) = input.get("mux") {
        fields(
            m,
            &[
                "enabled",
                "concurrency",
                "xudpConcurrency",
                "xudpProxyUDP443",
            ],
            "Xray Mux",
        )?;
        if m.get("enabled").is_some_and(|v| v != false) {
            return Err("Включённый Xray Mux пока не поддерживается.".into());
        }
    }
    if let Some(stream) = input.get("streamSettings") {
        fields(
            stream,
            &[
                "network",
                "security",
                "tlsSettings",
                "realitySettings",
                "tcpSettings",
                "rawSettings",
                "wsSettings",
                "grpcSettings",
                "xhttpSettings",
                "hysteriaSettings",
                "finalmask",
            ],
            "Xray transport",
        )?;
        let network = s(stream, "network");
        match network {
            "" | "tcp" | "raw" => {
                for key in ["tcpSettings", "rawSettings"] {
                    if let Some(t) = stream.get(key) {
                        fields(t, &["header"], "TCP")?;
                        if let Some(h) = t.get("header") {
                            fields(h, &["type"], "TCP header")?;
                            if s(h, "type") != "none" {
                                return Err("TCP header не поддерживается.".into());
                            }
                        }
                    }
                }
            }
            "ws" => {
                if let Some(t) = stream.get("wsSettings") {
                    fields(t, &["path", "host", "headers"], "WebSocket")?;
                    if t.get("headers").is_some_and(|h| {
                        h.as_object()
                            .is_none_or(|h| h.values().any(|v| !v.is_string()))
                    }) {
                        return Err("WebSocket: неверные headers.".into());
                    }
                }
            }
            "grpc" => {
                if let Some(t) = stream.get("grpcSettings") {
                    fields(t, &["serviceName", "multiMode", "authority"], "gRPC")?;
                }
            }
            "xhttp" => validate_xhttp(
                out["streamSettings"]
                    .get_mut("xhttpSettings")
                    .ok_or("XHTTP: нет настроек транспорта.")?,
            )?,
            "hysteria" if protocol == "hysteria" => {
                let h = stream
                    .get("hysteriaSettings")
                    .ok_or("Hysteria: нет настроек транспорта.")?;
                fields(h, &["version", "auth"], "Hysteria transport")?;
                if h.get("version") != Some(&json!(2)) || s(h, "auth").is_empty() {
                    return Err("Hysteria: нужны version=2 и auth.".into());
                }
            }
            _ => return Err("Xray: неподдерживаемый транспорт.".into()),
        }
        if protocol == "hysteria" && network != "hysteria" {
            return Err("Hysteria требует транспорт hysteria.".into());
        }
        // Do not accept settings for an inactive transport: that would silently discard behavior.
        for (key, net) in [
            ("xhttpSettings", "xhttp"),
            ("wsSettings", "ws"),
            ("grpcSettings", "grpc"),
            ("hysteriaSettings", "hysteria"),
        ] {
            if stream.get(key).is_some() && network != net {
                return Err("Xray: параметры не соответствуют транспорту.".into());
            }
        }
        if !["", "tcp", "raw"].contains(&network)
            && ["tcpSettings", "rawSettings"]
                .iter()
                .any(|k| stream.get(*k).is_some())
        {
            return Err("Xray: TCP settings переданы для другого транспорта.".into());
        }
        if let Some(mask) = stream.get("finalmask") {
            if protocol != "hysteria" {
                return Err("FinalMask поддерживается только для Hysteria2.".into());
            }
            fields(mask, &["quicParams"], "FinalMask")?;
            if let Some(q) = mask.get("quicParams") {
                fields(q, &["congestion", "debug"], "QUIC")?;
                out["streamSettings"]["finalmask"]["quicParams"]["debug"] = json!(false);
            }
        }
        let security = s(stream, "security");
        if (security != "tls" && stream.get("tlsSettings").is_some())
            || (security != "reality" && stream.get("realitySettings").is_some())
        {
            return Err("Xray: параметры не соответствуют защите транспорта.".into());
        }
        if security == "tls" || security == "reality" {
            let key = if security == "tls" {
                "tlsSettings"
            } else {
                "realitySettings"
            };
            let t = stream.get(key).ok_or("Xray: нет TLS/Reality settings.")?;
            fields(
                t,
                &[
                    "serverName",
                    "allowInsecure",
                    "alpn",
                    "fingerprint",
                    "publicKey",
                    "password",
                    "shortId",
                    "spiderX",
                    "show",
                ],
                "TLS/Reality",
            )?;
            disabled(t, "allowInsecure")?;
            if s(t, "serverName").is_empty() {
                out["streamSettings"][key]["serverName"] = json!(host);
            }
            let mut query = BTreeMap::new();
            for (src, dst) in [
                ("serverName", "sni"),
                ("fingerprint", "fp"),
                ("publicKey", "pbk"),
                ("shortId", "sid"),
                ("spiderX", "spx"),
            ] {
                if !s(t, src).is_empty() {
                    query.insert(dst.into(), s(t, src).into());
                }
            }
            if !s(t, "password").is_empty() {
                if query.get("pbk").is_some_and(|k| k != s(t, "password")) {
                    return Err("Reality: ключи противоречат друг другу.".into());
                }
                query.insert("pbk".into(), s(t, "password").into());
            }
            crate::import::tls(&query, &host, security)?;
            if let Some(alpn) = t.get("alpn")
                && alpn
                    .as_array()
                    .is_none_or(|a| a.iter().any(|v| !v.is_string()))
            {
                return Err("TLS: неверный alpn.".into());
            }
            if security == "reality" {
                out["streamSettings"][key]["show"] = json!(false);
                if s(t, "fingerprint").is_empty() {
                    out["streamSettings"][key]["fingerprint"] = json!("chrome");
                }
            }
        } else if protocol != "shadowsocks" || !["", "none"].contains(&security) {
            return Err("Для этого подключения требуется TLS или Reality.".into());
        }
        if protocol == "hysteria" && security != "tls" {
            return Err("Hysteria2 требует TLS.".into());
        }
    } else if protocol != "shadowsocks" {
        return Err("Xray: нет защищённого транспорта.".into());
    }
    let name = s(input, "tag")
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect::<String>();
    out["tag"] = json!("proxy");
    Ok(Parsed {
        name: if name.is_empty() { host.clone() } else { name },
        host,
        protocol: if protocol == "hysteria" {
            "hysteria2".into()
        } else {
            protocol.into()
        },
        engine: EngineKind::Xray,
        outbound: out,
    })
}

pub fn profile(v: &Value) -> Result<Profile> {
    let parsed = parse_outbound(v)?;
    Ok(Profile {
        name: parsed.name,
        uri: format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&parsed.outbound).map_err(|_| "Ошибка Xray JSON.")?)
        ),
    })
}
pub fn parse_uri(uri: &str) -> Result<Parsed> {
    let bytes = URL_SAFE_NO_PAD
        .decode(uri.strip_prefix(PREFIX).ok_or("Неверный Xray профиль.")?)
        .map_err(|_| "Неверная кодировка Xray профиля.")?;
    let v = serde_json::from_slice(&bytes).map_err(|_| "Неверный Xray JSON.")?;
    parse_outbound(&v)
}

pub fn from_vless(v: &Value, q: &BTreeMap<String, String>) -> Result<Value> {
    let security = q.get("security").map(String::as_str).unwrap_or("none");
    let t = &v["tls"];
    let mut tls = json!({"serverName":t["server_name"],"fingerprint":t["utls"]["fingerprint"].as_str().unwrap_or("chrome")});
    if let Some(alpn) = t.get("alpn") {
        tls["alpn"] = alpn.clone();
    }
    if security == "reality" {
        tls["publicKey"] = t["reality"]["public_key"].clone();
        tls["shortId"] = t["reality"]["short_id"].clone();
        tls["spiderX"] = json!(q.get("spx").map(String::as_str).unwrap_or("/"));
        tls["show"] = json!(false);
    } else {
        tls["allowInsecure"] = json!(false);
    }
    let network = q.get("type").map(String::as_str).unwrap_or("tcp");
    let mut stream = json!({"network":network,"security":security});
    match network {
        "tcp" => {}
        "xhttp" => {
            let get =
                |key: &str, default: &str| q.get(key).cloned().unwrap_or_else(|| default.into());
            let mut xhttp =
                json!({"path":get("path","/"),"host":get("host",""),"mode":get("mode","auto")});
            if let Some(extra) = q.get("extra") {
                xhttp["extra"] =
                    serde_json::from_str(extra).map_err(|_| "XHTTP extra: неверный JSON.")?;
            }
            stream["xhttpSettings"] = xhttp;
        }
        _ => return Err("Xray: неподдерживаемый транспорт VLESS-ссылки.".into()),
    }
    stream[if security == "reality" {
        "realitySettings"
    } else {
        "tlsSettings"
    }] = tls;
    let out = json!({"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":v["server"],"port":v["server_port"],"users":[{"id":v["uuid"],"encryption":"none","flow":v["flow"].as_str().unwrap_or("")}]}]},"streamSettings":stream});
    Ok(parse_outbound(&out)?.outbound)
}

pub fn config(outbound: Value, port: u16) -> Value {
    json!({"log":{"access":"none","error":"none","loglevel":"none","dnsLog":false},
        "inbounds":[{"tag":"bridge","listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"auth":"noauth","udp":true}}],
        "outbounds":[outbound]})
}
