use crate::{MAX_IMPORT, Result};
use base64::{Engine, engine::general_purpose as b64};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, time::Duration};
use url::Url;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub uri: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    SingBox,
    Xray,
}

pub struct Parsed {
    pub name: String,
    pub host: String,
    pub protocol: String,
    pub outbound: Value,
    pub engine: EngineKind,
}

fn decode(s: &str) -> Result<String> {
    percent_decode_str(s)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| "Некорректная кодировка ссылки.".into())
}

fn from_base64(s: &str) -> Result<String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    [
        b64::STANDARD,
        b64::STANDARD_NO_PAD,
        b64::URL_SAFE,
        b64::URL_SAFE_NO_PAD,
    ]
    .iter()
    .find_map(|engine| engine.decode(&s).ok())
    .and_then(|v| String::from_utf8(v).ok())
    .ok_or_else(|| "Некорректный Base64.".into())
}

fn clean_name(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(80).collect()
}

pub(crate) fn validate_uuid(s: &str) -> Result<()> {
    if s.len() != 36
        || !s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
    {
        return Err("Неверный UUID сервера.".into());
    }
    Ok(())
}

pub(crate) fn tls(q: &BTreeMap<String, String>, host: &str, security: &str) -> Result<Value> {
    if security != "tls" && security != "reality" {
        return Err("Для VLESS/Trojan требуется TLS или Reality.".into());
    }
    if q.get("sni").zip(q.get("peer")).is_some_and(|(a, b)| a != b) {
        return Err("Параметры sni и peer противоречат друг другу.".into());
    }
    if security != "reality" && ["pbk", "sid", "spx"].iter().any(|key| q.contains_key(*key)) {
        return Err("Параметры Reality требуют security=reality.".into());
    }
    if q.get("spx").is_some_and(|s| !s.is_empty() && s != "/") {
        return Err("Пользовательский spiderX пока не поддерживается.".into());
    }
    let name = q
        .get("sni")
        .or_else(|| q.get("peer"))
        .map_or(host, String::as_str);
    let mut result = json!({"enabled":true, "server_name":name, "insecure":false});
    if let Some(alpn) = q.get("alpn") {
        result["alpn"] = json!(
            alpn.split(',')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        );
    }
    if let Some(fp) = q.get("fp") {
        if ![
            "chrome",
            "firefox",
            "edge",
            "safari",
            "360",
            "qq",
            "ios",
            "android",
            "random",
            "randomized",
        ]
        .contains(&fp.as_str())
        {
            return Err("Неподдерживаемый TLS fingerprint.".into());
        }
        result["utls"] = json!({"enabled":true,"fingerprint":fp});
    }
    if security == "reality" {
        let key = q
            .get("pbk")
            .ok_or("В Reality отсутствует публичный ключ.")?;
        if b64::URL_SAFE_NO_PAD
            .decode(key)
            .map_or(true, |v| v.len() != 32)
        {
            return Err("Неверный публичный ключ Reality.".into());
        }
        let sid = q.get("sid").map_or("", String::as_str);
        if sid.len() > 16
            || !sid.len().is_multiple_of(2)
            || !sid.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err("Неверный short ID Reality.".into());
        }
        result["reality"] = json!({"enabled":true,"public_key":key,"short_id":sid});
        if result.get("utls").is_none() {
            result["utls"] = json!({"enabled":true,"fingerprint":"chrome"});
        }
    }
    Ok(result)
}

fn transport(q: &BTreeMap<String, String>, out: &mut Value) -> Result<()> {
    let kind = q.get("type").map_or("tcp", String::as_str);
    if q.contains_key("extra") || q.get("mode").is_some_and(|s| kind != "grpc" || s != "gun") {
        return Err("Параметры mode/extra не соответствуют выбранному транспорту.".into());
    }
    if (kind != "ws"
        && ["host", "path"]
            .iter()
            .any(|k| q.get(*k).is_some_and(|s| !s.is_empty())))
        || (kind != "grpc" && q.get("serviceName").is_some_and(|s| !s.is_empty()))
    {
        return Err("Параметры не соответствуют выбранному транспорту.".into());
    }
    match q.get("type").map_or("tcp", String::as_str) {
        "tcp" => {
            if q.get("headerType").is_some_and(|s| s != "none") {
                return Err("TCP headerType не поддерживается.".into());
            }
        }
        "ws" => {
            out["transport"] =
                json!({"type":"ws", "path":q.get("path").map_or("/", String::as_str)});
            if let Some(host) = q.get("host") {
                out["transport"]["headers"] = json!({"Host":host});
            }
        }
        "grpc" => {
            out["transport"] = json!({"type":"grpc", "service_name":q.get("serviceName").map_or("", String::as_str)});
        }
        _ => {
            return Err(
                "Этот транспорт не поддерживается для данного протокола. XHTTP-ссылки поддерживаются для VLESS."
                    .into(),
            );
        }
    }
    Ok(())
}

fn xray_mux(q: &BTreeMap<String, String>) -> Result<()> {
    match q.get("mux").map(String::as_str) {
        None | Some("0" | "false") => {}
        Some("1" | "true") => {
            return Err("Xray Mux включён в ссылке и пока не поддерживается.".into());
        }
        _ => return Err("Параметр mux должен быть true/false или 1/0.".into()),
    }
    if q.get("concurrency")
        .is_some_and(|value| value.parse::<i32>().is_err())
    {
        return Err("Параметр concurrency должен быть целым числом.".into());
    }
    // Xray defaults mux.enabled to false. Exporters may include its dormant
    // concurrency setting anyway. It does not enable multiplexing by itself;
    // sing-box multiplex uses a different wire protocol and is not a substitute.
    Ok(())
}

pub fn parse_uri(uri: &str) -> Result<Parsed> {
    if uri.len() > 65536 {
        return Err("Ссылка слишком длинная.".into());
    }
    if uri.starts_with(crate::xray::PREFIX) {
        return crate::xray::parse_uri(uri);
    }
    if uri.starts_with("vmess://") {
        return parse_vmess(uri);
    }
    // Legacy Shadowsocks puts the entire authority in Base64.
    let expanded;
    let uri = if uri.starts_with("ss://") && !uri.split('#').next().unwrap_or("").contains('@') {
        let (body, tag) = uri[5..].split_once('#').unwrap_or((&uri[5..], ""));
        expanded = format!("ss://{}#{}", from_base64(body)?, tag);
        expanded.as_str()
    } else {
        uri
    };
    let u = Url::parse(uri).map_err(|_| "Некорректная ссылка сервера.")?;
    let host = u
        .host_str()
        .ok_or("В ссылке нет адреса сервера.")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    if host.is_empty() || host.len() > 253 {
        return Err("Неверный адрес сервера.".into());
    }
    let port = u.port().unwrap_or(443);
    if port == 0 {
        return Err("Порт должен быть от 1 до 65535.".into());
    }
    let mut q = BTreeMap::new();
    for (key, value) in u.query_pairs() {
        if q.insert(key.into_owned(), value.into_owned()).is_some() {
            return Err("В ссылке повторяются параметры.".into());
        }
    }
    if u.scheme() == "vless" {
        // Provider grouping/priority annotations do not change transport or routing.
        q.remove("x-durev-block");
        q.remove("x-durev-prio");
        if let Some(flag) = q.remove("x-durev-sni-change") {
            let enabled = match flag.as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => {
                    return Err(
                        "Неверное значение x-durev-sni-change: нужен true/false или 1/0.".into(),
                    );
                }
            };
            // This undocumented provider hint is not a core setting. Use only
            // the explicit SNI in the link; never invent a replacement name.
            if enabled
                && !["sni", "peer"]
                    .iter()
                    .any(|k| q.get(*k).is_some_and(|v| !v.is_empty()))
            {
                return Err("Для x-durev-sni-change нужен явно указанный sni или peer.".into());
            }
        }
    }
    for key in q.keys() {
        if ![
            "security",
            "sni",
            "peer",
            "fp",
            "pbk",
            "sid",
            "spx",
            "flow",
            "encryption",
            "type",
            "path",
            "host",
            "serviceName",
            "headerType",
            "alpn",
            "allowInsecure",
            "insecure",
            "obfs",
            "obfs-password",
            "mux",
            "concurrency",
            "mode",
            "extra",
        ]
        .contains(&key.as_str())
        {
            // Query keys can themselves contain a token or a nested private URL.
            return Err(
                "Ссылка содержит неподдерживаемый параметр. Проверьте формат или обновите Eivro."
                    .into(),
            );
        }
    }
    if ["allowInsecure", "insecure"]
        .iter()
        .any(|k| q.get(*k).is_some_and(|v| v != "0" && v != "false"))
    {
        return Err("Ссылки с отключённой проверкой TLS не принимаются.".into());
    }
    let protocol = match u.scheme() {
        "vless" => "vless",
        "trojan" => "trojan",
        "ss" => "shadowsocks",
        "hy2" | "hysteria2" => "hysteria2",
        _ => return Err("Нужна ссылка VLESS, VMess, Trojan, Shadowsocks или Hysteria2.".into()),
    };
    let allowed: &[&str] = match protocol {
        "vless" => &[
            "security",
            "sni",
            "peer",
            "fp",
            "pbk",
            "sid",
            "spx",
            "flow",
            "encryption",
            "type",
            "path",
            "host",
            "serviceName",
            "headerType",
            "alpn",
            "allowInsecure",
            "insecure",
            "mux",
            "concurrency",
            "mode",
            "extra",
        ],
        "trojan" => &[
            "security",
            "sni",
            "peer",
            "fp",
            "type",
            "path",
            "host",
            "serviceName",
            "headerType",
            "alpn",
            "allowInsecure",
            "insecure",
            "mux",
            "concurrency",
            "mode",
        ],
        "hysteria2" => &[
            "security",
            "sni",
            "peer",
            "alpn",
            "allowInsecure",
            "insecure",
            "obfs",
            "obfs-password",
        ],
        _ => &[],
    };
    if q.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err("Параметры не поддерживаются для этого протокола.".into());
    }
    if matches!(protocol, "vless" | "trojan") {
        xray_mux(&q)?;
    }
    if !u.path().is_empty() && u.path() != "/" {
        return Err(
            "Путь транспорта передаётся параметром path, а не после адреса сервера.".into(),
        );
    }
    let user = decode(u.username())?;
    if user.is_empty() {
        return Err("В ссылке нет ключа доступа.".into());
    }
    let mut out = json!({"type":protocol,"tag":"proxy","server":host,"server_port":port});
    let mut engine = EngineKind::SingBox;
    match protocol {
        "vless" => {
            validate_uuid(&user)?;
            if u.password().is_some() {
                return Err("Некорректные данные VLESS.".into());
            }
            if q.get("encryption").is_some_and(|v| v != "none") {
                return Err("Этот вариант VLESS encryption пока не поддерживается.".into());
            }
            out["uuid"] = json!(user);
            let security = q.get("security").map_or("none", String::as_str);
            out["tls"] = tls(&q, &host, security)?;
            if let Some(flow) = q.get("flow") {
                if !flow.is_empty() && flow != "xtls-rprx-vision" {
                    return Err("Неподдерживаемый VLESS flow.".into());
                }
                if !flow.is_empty() && q.get("type").is_some_and(|s| s != "tcp") {
                    return Err("XTLS Vision требует TCP.".into());
                }
                out["flow"] = json!(flow);
            }
            if q.get("type").is_some_and(|v| v == "xhttp") {
                if q.get("serviceName").is_some_and(|v| !v.is_empty())
                    || q.get("headerType").is_some_and(|v| v != "none")
                {
                    return Err("XHTTP: параметры другого транспорта.".into());
                }
                out = crate::xray::from_vless(&out, &q)?;
                engine = EngineKind::Xray;
            } else {
                transport(&q, &mut out)?;
                // Current Xray Reality servers require a ClientHello that our
                // sing-box core does not send. Reuse the existing Xray bridge.
                if security == "reality" && q.get("type").is_none_or(|v| v == "tcp") {
                    out = crate::xray::from_vless(&out, &q)?;
                    engine = EngineKind::Xray;
                }
            }
        }
        "trojan" => {
            if u.password().is_some() {
                return Err("Двоеточие в пароле нужно кодировать как %3A.".into());
            }
            out["password"] = json!(user);
            out["tls"] = tls(&q, &host, q.get("security").map_or("tls", String::as_str))?;
            transport(&q, &mut out)?;
        }
        "shadowsocks" => {
            if !q.is_empty() {
                return Err(
                    "Плагины и дополнительные параметры Shadowsocks пока не поддерживаются.".into(),
                );
            }
            let auth = if let Some(p) = u.password() {
                format!("{}:{}", user, decode(p)?)
            } else {
                from_base64(&user)?
            };
            let (method, password) = auth
                .split_once(':')
                .ok_or("В Shadowsocks нет метода шифрования или пароля.")?;
            if ![
                "aes-128-gcm",
                "aes-256-gcm",
                "chacha20-ietf-poly1305",
                "2022-blake3-aes-128-gcm",
                "2022-blake3-aes-256-gcm",
                "2022-blake3-chacha20-poly1305",
            ]
            .contains(&method)
                || password.is_empty()
            {
                return Err(
                    "Нужен поддерживаемый AEAD-метод Shadowsocks и непустой пароль.".into(),
                );
            }
            out["method"] = json!(method);
            out["password"] = json!(password);
        }
        "hysteria2" => {
            let password = if let Some(p) = u.password() {
                format!("{}:{}", user, decode(p)?)
            } else {
                user
            };
            out["password"] = json!(password);
            if q.contains_key("fp")
                || q.get("security").is_some_and(|s| s != "tls")
                || q.contains_key("type")
            {
                return Err("Неподдерживаемые настройки Hysteria2.".into());
            }
            out["tls"] = tls(&q, &host, "tls")?;
            if q.contains_key("obfs-password") && !q.contains_key("obfs") {
                return Err("Пароль obfs требует выбора obfs=salamander.".into());
            }
            if let Some(obfs) = q.get("obfs") {
                if obfs != "salamander" {
                    return Err("Поддерживается obfs=salamander.".into());
                }
                out["obfs"] = json!({"type":obfs,"password":q.get("obfs-password").ok_or("Нет пароля obfs.")?});
            }
        }
        _ => unreachable!(),
    }
    let name = clean_name(&decode(u.fragment().unwrap_or(&host))?);
    Ok(Parsed {
        name: if name.is_empty() { host.clone() } else { name },
        host,
        protocol: protocol.into(),
        outbound: out,
        engine,
    })
}

fn parse_vmess(uri: &str) -> Result<Parsed> {
    let data = from_base64(&uri[8..])?;
    let v: Value = serde_json::from_str(&data).map_err(|_| "Некорректный VMess JSON.")?;
    let fields = v.as_object().ok_or("VMess должен быть JSON-объектом.")?;
    if fields.keys().any(|k| {
        ![
            "v",
            "ps",
            "add",
            "port",
            "id",
            "aid",
            "scy",
            "net",
            "type",
            "host",
            "path",
            "tls",
            "sni",
            "alpn",
            "fp",
            "allowInsecure",
        ]
        .contains(&k.as_str())
    }) {
        return Err("В VMess есть неподдерживаемые параметры.".into());
    }
    let s = |key: &str| v.get(key).and_then(Value::as_str).unwrap_or("");
    let host = s("add");
    if host.is_empty() || host.len() > 253 {
        return Err("Нет адреса VMess.".into());
    }
    let uuid = s("id");
    validate_uuid(uuid)?;
    let port = v
        .get("port")
        .and_then(Value::as_u64)
        .or_else(|| s("port").parse().ok())
        .filter(|p| *p > 0 && *p <= 65535)
        .ok_or("Неверный порт VMess.")?;
    if s("tls") != "tls" {
        return Err("В этой версии VMess требует TLS.".into());
    }
    if v.get("allowInsecure")
        .is_some_and(|v| v != false && v != "false" && v != "0" && v != 0)
    {
        return Err("Проверка TLS обязательна.".into());
    }
    let aid = v
        .get("aid")
        .and_then(Value::as_u64)
        .or_else(|| s("aid").parse().ok())
        .unwrap_or(0);
    if aid != 0 {
        return Err("Поддерживается только VMess AEAD (alterId=0).".into());
    }
    if !s("type").is_empty() && s("type") != "none" {
        return Err("VMess headerType не поддерживается.".into());
    }
    let mut q = BTreeMap::new();
    q.insert(
        "type".into(),
        if s("net").is_empty() { "tcp" } else { s("net") }.into(),
    );
    for (src, dst) in [
        ("sni", "sni"),
        ("host", "host"),
        ("path", "path"),
        ("alpn", "alpn"),
        ("fp", "fp"),
    ] {
        if !s(src).is_empty() {
            q.insert(dst.into(), s(src).into());
        }
    }
    if s("net") == "grpc" {
        q.remove("path");
        q.insert("serviceName".into(), s("path").into());
    }
    let cipher = if s("scy").is_empty() {
        "auto"
    } else {
        s("scy")
    };
    if !["auto", "aes-128-gcm", "chacha20-poly1305"].contains(&cipher) {
        return Err("Неподдерживаемое шифрование VMess.".into());
    }
    let mut out = json!({"type":"vmess","tag":"proxy","server":host,"server_port":port,"uuid":uuid,"security":cipher,"alter_id":0,"tls":tls(&q,host,"tls")?});
    transport(&q, &mut out)?;
    Ok(Parsed {
        name: clean_name(if s("ps").is_empty() { host } else { s("ps") }),
        host: host.into(),
        protocol: "vmess".into(),
        outbound: out,
        engine: EngineKind::SingBox,
    })
}

pub fn import_text(text: &str) -> Result<Vec<Profile>> {
    if text.len() > MAX_IMPORT {
        return Err("Максимальный размер подписки — 2 МиБ.".into());
    }
    let text = text.trim();
    let decoded;
    let text = if !text.contains("://") {
        decoded = from_base64(text)?;
        decoded.as_str()
    } else {
        text
    };
    let mut result: Vec<Profile> = Vec::new();
    for (i, line) in text
        .lines()
        .filter(|s| !s.trim().is_empty() && !s.trim().starts_with('#'))
        .enumerate()
    {
        if i >= 256 {
            return Err("Максимум 256 серверов в подписке.".into());
        }
        let uri = line.trim();
        let parsed = parse_uri(uri).map_err(|e| format!("Строка {}: {e}", i + 1))?;
        if !result.iter().any(|p| p.uri == uri) {
            result.push(Profile {
                name: parsed.name,
                uri: uri.into(),
            });
        }
    }
    if result.is_empty() {
        return Err("Не найдено серверов.".into());
    }
    Ok(result)
}

pub fn fetch_subscription(input: &str) -> Result<Vec<Profile>> {
    crate::subscription::import_bytes(&download_subscription(input)?)
}

/// Download without applying provider configuration. Callers keep the body in memory.
pub fn download_subscription(input: &str) -> Result<Vec<u8>> {
    Ok(download_document(input)?.body)
}
pub struct Download {
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

fn download_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(status, _) => match status {
            401 | 403 => format!(
                "HTTP {status}: доступ к подписке запрещён. Проверьте ссылку и срок действия."
            ),
            404 | 410 => format!(
                "HTTP {status}: подписка не найдена или отозвана. Проверьте ссылку у провайдера."
            ),
            429 => "HTTP 429: провайдер ограничил частоту обновлений. Повторите позже.".into(),
            500..=599 => {
                format!("HTTP {status}: сервис подписок временно недоступен. Повторите позже.")
            }
            _ => format!("Сервис подписок вернул HTTP {status}. Обновление не применено."),
        },
        ureq::Error::Transport(transport) => {
            let mut cause = std::error::Error::source(&transport);
            while let Some(error) = cause {
                if error.downcast_ref::<std::io::Error>().is_some_and(|io| {
                    matches!(
                        io.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    )
                }) {
                    return "Время загрузки подписки истекло. Проверьте сеть и повторите позже."
                        .into();
                }
                cause = error.source();
            }
            match transport.kind() {
                ureq::ErrorKind::Dns => "Не удалось разрешить DNS-имя сервиса подписок. Проверьте сеть и DNS.".into(),
                // ureq also uses ConnectionFailed for TLS handshake/certificate errors.
                ureq::ErrorKind::ConnectionFailed => "Не удалось установить HTTPS-соединение с сервисом подписок. Проверьте сеть и TLS-сертификат провайдера.".into(),
                ureq::ErrorKind::BadStatus | ureq::ErrorKind::BadHeader => "Сервис подписок вернул некорректный HTTP-ответ.".into(),
                _ => "Не удалось загрузить подписку. Проверьте адрес, TLS и сеть.".into(),
            }
        }
    }
}

pub fn download_document(input: &str) -> Result<Download> {
    let mut url = Url::parse(input.trim()).map_err(|_| "Некорректный URL подписки.")?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err("Подписка должна быть HTTPS-ссылкой без HTTP Basic Auth.".into());
    }
    // Only HTTPS redirects, no cookies, Referer or URL in errors.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut redirects = 0;
    let response = loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or("Время загрузки подписки истекло.")?;
        // ureq's default connect timeout is independent of the request deadline.
        // Each redirect must share the remaining budget, including TCP connect.
        let agent = ureq::AgentBuilder::new()
            .resolver(move |netloc: &str| crate::resolver::resolve(netloc, deadline, None))
            .timeout_connect(remaining)
            .timeout(remaining)
            .redirects(0)
            .build();
        let response = agent
            .get(url.as_str())
            .timeout(remaining)
            .set("User-Agent", concat!("Eivro/", env!("CARGO_PKG_VERSION")))
            .set("Accept-Encoding", "identity")
            .call()
            .map_err(download_error)?;
        if [301, 302, 303, 307, 308].contains(&response.status()) {
            if redirects >= 3 {
                return Err("Слишком много перенаправлений подписки.".into());
            }
            url = url
                .join(
                    response
                        .header("Location")
                        .ok_or("В перенаправлении нет адреса.")?,
                )
                .map_err(|_| "Неверный адрес перенаправления.")?;
            if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
                return Err("Небезопасное перенаправление подписки.".into());
            }
            redirects += 1;
            continue;
        }
        if !(200..300).contains(&response.status()) {
            return Err("Сервер подписки вернул неожиданный HTTP-статус.".into());
        }
        break response;
    };
    let headers = [
        "profile-title",
        "profile-update-interval",
        "announce",
        "support-url",
        "profile-web-page-url",
        "subscription-userinfo",
    ]
    .iter()
    .filter_map(|key| {
        response
            .header(key)
            .map(|v| (key.to_string(), v.to_owned()))
    })
    .collect();
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take((MAX_IMPORT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "Ошибка чтения подписки.")?;
    if bytes.len() > MAX_IMPORT {
        return Err("Подписка больше 2 МиБ.".into());
    }
    Ok(Download {
        body: bytes,
        headers,
    })
}

#[cfg(test)]
mod subscription_download_tests {
    use super::download_error;

    #[test]
    fn http_errors_report_status_and_never_echo_response_text() {
        for status in [400, 401, 403, 404, 410, 429, 500, 502, 503] {
            let response = ureq::Response::new(
                status,
                "private-reason",
                "https://provider.example/sub/private-token secret-response-body",
            )
            .unwrap();
            let error = download_error(ureq::Error::Status(status, response));
            assert!(error.contains(&status.to_string()));
            for secret in [
                "private-reason",
                "private-token",
                "secret-response-body",
                "provider.example",
            ] {
                assert!(!error.contains(secret));
            }
        }
    }

    #[test]
    fn transport_timeouts_are_distinct_and_do_not_echo_error_details() {
        let error: ureq::Error = std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "https://provider.example/sub/private-token",
        )
        .into();
        let message = download_error(error);
        assert!(message.contains("Время загрузки"));
        assert!(!message.contains("private-token"));
        let error: ureq::Error = std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "private-connection-error",
        )
        .into();
        let message = download_error(error);
        assert!(!message.contains("private-connection-error"));
        assert!(message.contains("TLS"));
    }
}
