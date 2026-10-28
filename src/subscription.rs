//! Data-only subscription import. Provider DNS, routing, logging, paths and commands
//! are never passed to the core; supported endpoints are normalized to share links.
use crate::{
    MAX_IMPORT, Result,
    import::{Profile, import_text, parse_uri},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    io::{Cursor, Read},
    path::Path,
};
use url::Url;

const MAX_FILES: usize = 32;
const MAX_DEPTH: usize = 3;
const MAX_BASE64_LAYERS: usize = 2;

#[derive(Default)]
struct Budget {
    files: usize,
    expanded: usize,
    metadata: crate::catalog::Metadata,
}

pub fn import_bytes(data: &[u8]) -> Result<Vec<Profile>> {
    Ok(import_document(data)?.0)
}
pub fn import_document(data: &[u8]) -> Result<(Vec<Profile>, crate::catalog::Metadata)> {
    if data.len() > MAX_IMPORT {
        return Err("Подписка больше 2 МиБ.".into());
    }
    let mut budget = Budget::default();
    let mut profiles = parse(data, 0, &mut budget)?;
    let mut seen = std::collections::HashSet::new();
    profiles.retain(|p| seen.insert(p.uri.clone()));
    if profiles.is_empty() {
        return Err("В подписке не найдено поддерживаемых серверов.".into());
    }
    if profiles.len() > 256 {
        return Err("В подписке больше 256 серверов.".into());
    }
    Ok((profiles, budget.metadata))
}

fn read_limited(reader: impl Read, budget: &mut Budget) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let remaining = MAX_IMPORT.saturating_sub(budget.expanded);
    reader
        .take(remaining as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Архив повреждён или использует неподдерживаемое сжатие.")?;
    if data.len() > remaining {
        return Err("Распакованная подписка больше 2 МиБ.".into());
    }
    budget.expanded += data.len();
    Ok(data)
}

fn text_payload(text: &str) -> String {
    text.trim_start_matches('\u{feff}')
        .lines()
        .filter(|line| !line.trim().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn recognizable_text(text: &str) -> Result<bool> {
    let mut payload = text_payload(text);
    // Probe the same bounded wrappers as parse() so malformed configurations
    // cannot be mistaken for README text.
    for layer in 0..=MAX_BASE64_LAYERS {
        let text = payload.trim();
        if text.starts_with(['{', '['])
            || [
                "vless://",
                "vmess://",
                "trojan://",
                "ss://",
                "hy2://",
                "hysteria2://",
                crate::xray::PREFIX,
            ]
            .iter()
            .any(|prefix| {
                text.get(..prefix.len())
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
            })
        {
            return Ok(true);
        }
        if text.is_empty() || text.contains("://") {
            break;
        }
        let Some(decoded) = crate::catalog::decode_base64_bytes(text) else {
            break;
        };
        if layer == MAX_BASE64_LAYERS {
            return Err("Слишком много слоёв Base64 в подписке.".into());
        }
        // Recognition tolerates damaged text; parse() still requires valid UTF-8.
        payload = text_payload(&String::from_utf8_lossy(&decoded));
    }
    Ok(false)
}

fn member(name: &str, data: &[u8], depth: usize, budget: &mut Budget) -> Result<Vec<Profile>> {
    budget.files += 1;
    if budget.files > MAX_FILES {
        return Err("В архиве больше 32 файлов.".into());
    }
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".json")
        || lower.ends_with(".conf")
        || lower.ends_with(".zip")
        || lower.ends_with(".gz")
        || lower.ends_with(".tar")
    {
        return parse(data, depth, budget);
    }
    if lower.ends_with(".txt") || Path::new(name).extension().is_none() {
        // README and licenses are not configurations. Recognizable payloads remain strict.
        if data.starts_with(b"PK\x03\x04")
            || data.starts_with(b"PK\x05\x06")
            || data.starts_with(&[0x1f, 0x8b])
            || data.len() > 262 && &data[257..262] == b"ustar"
            || recognizable_text(&String::from_utf8_lossy(data))?
        {
            return parse(data, depth, budget);
        }
    }
    Ok(Vec::new())
}

fn parse(data: &[u8], depth: usize, budget: &mut Budget) -> Result<Vec<Profile>> {
    if depth > MAX_DEPTH {
        return Err("Слишком много вложенных архивов.".into());
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        let mut zip = zip::ZipArchive::new(Cursor::new(data)).map_err(|_| "Некорректный ZIP.")?;
        if zip.len() > MAX_FILES {
            return Err("В ZIP больше 32 записей.".into());
        }
        let mut all = Vec::new();
        for i in 0..zip.len() {
            let file = zip
                .by_index(i)
                .map_err(|_| "Зашифрованные и повреждённые ZIP не поддерживаются.")?;
            if file.is_dir() {
                continue;
            }
            if file.enclosed_name().is_none()
                || file.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000)
            {
                return Err("Небезопасный путь или ссылка в ZIP.".into());
            }
            if file.size() > MAX_IMPORT as u64 {
                return Err("Файл в архиве больше 2 МиБ.".into());
            }
            let name = file.name().to_owned();
            let bytes = read_limited(file, budget)?;
            all.extend(member(&name, &bytes, depth + 1, budget)?);
        }
        return Ok(all);
    }
    if data.starts_with(&[0x1f, 0x8b]) {
        let bytes = read_limited(flate2::read::GzDecoder::new(data), budget)?;
        return parse(&bytes, depth + 1, budget);
    }
    if data.len() > 262 && &data[257..262] == b"ustar" {
        let mut tar = tar::Archive::new(Cursor::new(data));
        let mut all = Vec::new();
        for entry in tar.entries().map_err(|_| "Некорректный TAR.")? {
            let entry = entry.map_err(|_| "Некорректная запись TAR.")?;
            if entry.header().entry_type().is_dir() {
                continue;
            }
            if !entry.header().entry_type().is_file() {
                return Err("В TAR допустимы только обычные файлы.".into());
            }
            let path = entry.path().map_err(|_| "Неверный путь TAR.")?.into_owned();
            if path.is_absolute()
                || path
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir))
            {
                return Err("Небезопасный путь TAR.".into());
            }
            let bytes = read_limited(entry, budget)?;
            all.extend(member(&path.to_string_lossy(), &bytes, depth + 1, budget)?);
        }
        return Ok(all);
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| "Нужны UTF-8, ZIP или gzip/tar.gz. RAR и 7z не поддерживаются.")?
        .trim_start_matches('\u{feff}')
        .trim();
    budget.metadata.comments(text);
    let mut payload = text_payload(text);
    for layer in 0..=MAX_BASE64_LAYERS {
        let content = payload.trim();
        if content.is_empty() {
            return Err("Сервис вернул пустую подписку или только информацию без серверов.".into());
        }
        if content.starts_with('<') {
            return Err("Сервис вернул HTML/XML-страницу вместо подписки. Проверьте ссылку и доступ у провайдера.".into());
        }
        if content.starts_with(['{', '[']) {
            let json: Value =
                serde_json::from_str(content).map_err(|_| "Некорректный JSON подписки.")?;
            return json_profiles(&json, 0);
        }
        if content.contains("://") {
            return import_text(content);
        }
        if layer == MAX_BASE64_LAYERS {
            break;
        }
        let decoded = crate::catalog::decode_base64(content)
            .ok_or("Неизвестный формат подписки: нужны ссылки, JSON, Base64 или архив.")?;
        budget
            .metadata
            .comments(decoded.trim_start_matches('\u{feff}').trim());
        payload = text_payload(&decoded);
    }
    Err("Слишком много слоёв Base64 в подписке.".into())
}

pub fn import_file(path: &Path) -> Result<Vec<Profile>> {
    Ok(import_file_document(path)?.0)
}
pub fn import_file_document(path: &Path) -> Result<(Vec<Profile>, crate::catalog::Metadata)> {
    let f = std::fs::File::open(path).map_err(|_| "Не удалось открыть файл подписки.")?;
    if !f
        .metadata()
        .map_err(|_| "Не удалось проверить файл.")?
        .is_file()
    {
        return Err("Выберите обычный файл.".into());
    }
    let data = read_limited(f, &mut Budget::default())?;
    import_document(&data)
}

fn string<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
fn number(v: &Value, key: &str) -> Option<u64> {
    v.get(key)
        .and_then(Value::as_u64)
        .or_else(|| string(v, key).parse().ok())
}
fn allowed(v: &Value, fields: &[&str]) -> Result<()> {
    let obj = v
        .as_object()
        .ok_or("Ожидался JSON-объект параметров сервера.")?;
    if obj.keys().any(|s| !fields.contains(&s.as_str())) {
        return Err("JSON содержит неподдерживаемые параметры подключения. Требуется расширить импорт этого формата.".into());
    }
    Ok(())
}

fn json_profiles(v: &Value, depth: usize) -> Result<Vec<Profile>> {
    if depth > 5 {
        return Err("JSON слишком глубоко вложен.".into());
    }
    let mut out = Vec::new();
    if let Some(list) = v.as_array() {
        if list.len() > 256 {
            return Err("В JSON больше 256 записей.".into());
        }
        for item in list {
            out.extend(json_profiles(item, depth + 1)?);
            if out.len() > 256 {
                return Err("Слишком много серверов.".into());
            }
        }
    } else if let Some(text) = v.as_str() {
        out = import_text(text)?;
    } else if let Some(list) = v.get("outbounds").filter(|_| v.get("type").is_none()) {
        out = json_profiles(list, depth + 1)?;
        if out.len() == 1 && !string(v, "remarks").is_empty() {
            out[0].name = clean(string(v, "remarks"));
        }
    } else if let Some(list) = v.get("configs") {
        out = json_profiles(list, depth + 1)?;
    } else if v.get("protocol").is_some() {
        if let Some(profile) = xray(v)? {
            out.push(profile);
        }
    } else if v.get("type").is_some() {
        if let Some(profile) = singbox(v)? {
            out.push(profile);
        }
    } else {
        return Err(
            "Неизвестная схема JSON. Поддерживаются outbounds Xray/sing-box и массив конфигураций."
                .into(),
        );
    }
    Ok(out)
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(80).collect()
}
fn make_uri(
    scheme: &str,
    server: &str,
    port: u64,
    auth: &str,
    name: &str,
    q: &[(String, String)],
) -> Result<Profile> {
    if server.is_empty() || port == 0 || port > 65535 {
        return Err("В JSON отсутствует адрес или правильный порт сервера.".into());
    }
    let mut u = Url::parse(&format!("{scheme}://placeholder.invalid"))
        .map_err(|_| "Неизвестный протокол.")?;
    u.set_host(Some(server))
        .map_err(|_| "Неверный адрес сервера.")?;
    u.set_port(Some(port as u16))
        .map_err(|_| "Неверный порт.")?;
    let auth =
        percent_encoding::utf8_percent_encode(auth, percent_encoding::NON_ALPHANUMERIC).to_string();
    u.set_username(&auth).map_err(|_| "Некорректный ключ.")?;
    if !q.is_empty() {
        u.query_pairs_mut()
            .extend_pairs(q.iter().map(|(k, v)| (k, v)));
    }
    u.set_fragment(Some(name));
    let uri = u.to_string();
    let parsed = parse_uri(&uri)?;
    Ok(Profile {
        name: if name.is_empty() {
            parsed.name
        } else {
            clean(name)
        },
        uri,
    })
}

fn add(q: &mut Vec<(String, String)>, key: &str, value: &str) {
    if !value.is_empty() {
        q.push((key.into(), value.into()));
    }
}
fn add_alpn(q: &mut Vec<(String, String)>, v: &Value) {
    if let Some(values) = v.get("alpn").and_then(Value::as_array) {
        add(
            q,
            "alpn",
            &values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
}

fn singbox(v: &Value) -> Result<Option<Profile>> {
    let kind = string(v, "type");
    if ["direct", "block", "dns", "selector", "urltest"].contains(&kind) {
        return Ok(None);
    }
    if !["vless", "vmess", "trojan", "shadowsocks", "hysteria2"].contains(&kind) {
        return Err("Неподдерживаемый протокол в sing-box JSON.".into());
    }
    allowed(
        v,
        &[
            "type",
            "tag",
            "server",
            "server_port",
            "uuid",
            "password",
            "method",
            "tls",
            "transport",
            "flow",
            "security",
            "alter_id",
            "obfs",
        ],
    )?;
    let server = string(v, "server");
    let port = number(v, "server_port").ok_or("В JSON нет порта.")?;
    let name = string(v, "tag");
    let mut q = Vec::new();
    if kind != "shadowsocks" {
        let tls = v.get("tls").ok_or("Для этого подключения нужен TLS.")?;
        allowed(
            tls,
            &[
                "enabled",
                "server_name",
                "insecure",
                "alpn",
                "utls",
                "reality",
            ],
        )?;
        if tls.get("enabled") != Some(&Value::Bool(true))
            || tls.get("insecure").is_some_and(|x| x != false)
        {
            return Err("В JSON TLS выключен или проверка сертификата отключена.".into());
        }
        add(&mut q, "sni", string(tls, "server_name"));
        add_alpn(&mut q, tls);
        if let Some(utls) = tls.get("utls") {
            allowed(utls, &["enabled", "fingerprint"])?;
            if utls.get("enabled") == Some(&Value::Bool(true)) {
                add(&mut q, "fp", string(utls, "fingerprint"));
            }
        }
        let reality = tls
            .get("reality")
            .filter(|r| r.get("enabled") == Some(&Value::Bool(true)));
        add(
            &mut q,
            "security",
            if reality.is_some() { "reality" } else { "tls" },
        );
        if let Some(r) = reality {
            allowed(r, &["enabled", "public_key", "short_id"])?;
            add(&mut q, "pbk", string(r, "public_key"));
            add(&mut q, "sid", string(r, "short_id"));
        }
    }
    if let Some(t) = v.get("transport") {
        allowed(t, &["type", "path", "headers", "service_name"])?;
        add(&mut q, "type", string(t, "type"));
        add(&mut q, "path", string(t, "path"));
        add(&mut q, "serviceName", string(t, "service_name"));
        if let Some(h) = t.get("headers") {
            allowed(h, &["Host"])?;
            add(&mut q, "host", string(h, "Host"));
        }
    }
    add(&mut q, "flow", string(v, "flow"));
    if let Some(obfs) = v.get("obfs") {
        allowed(obfs, &["type", "password"])?;
        add(&mut q, "obfs", string(obfs, "type"));
        add(&mut q, "obfs-password", string(obfs, "password"));
    }
    if kind == "vmess" {
        let val = |key: &str| {
            q.iter()
                .find(|(k, _)| k == key)
                .map_or("", |(_, v)| v.as_str())
        };
        if val("security") != "tls" {
            return Err("VMess Reality не поддерживается.".into());
        }
        let net = if val("type").is_empty() {
            "tcp"
        } else {
            val("type")
        };
        let data = json!({"v":"2","ps":name,"add":server,"port":port,"id":string(v,"uuid"),"aid":number(v,"alter_id").unwrap_or(0),"scy":string(v,"security"),"net":net,"type":"none","host":val("host"),"path":if net=="grpc"{val("serviceName")}else{val("path")},"tls":"tls","sni":val("sni"),"fp":val("fp"),"alpn":val("alpn")});
        let uri = format!("vmess://{}", STANDARD.encode(data.to_string()));
        let parsed = parse_uri(&uri)?;
        return Ok(Some(Profile {
            name: parsed.name,
            uri,
        }));
    }
    let (scheme, auth) = match kind {
        "vless" => ("vless", string(v, "uuid").to_owned()),
        "shadowsocks" => (
            "ss",
            STANDARD.encode(format!("{}:{}", string(v, "method"), string(v, "password"))),
        ),
        "trojan" => ("trojan", string(v, "password").into()),
        _ => ("hysteria2", string(v, "password").into()),
    };
    Ok(Some(make_uri(scheme, server, port, &auth, name, &q)?))
}

fn xray(v: &Value) -> Result<Option<Profile>> {
    let kind = string(v, "protocol");
    if ["freedom", "blackhole", "dns", "loopback"].contains(&kind) {
        return Ok(None);
    }
    crate::xray::profile(v).map(Some)
}
