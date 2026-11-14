use base64::{Engine, engine::general_purpose::STANDARD};
use eivro::{
    catalog,
    import::{EngineKind, parse_uri},
    storage::Settings,
};
use serde_json::json;
use std::io::{Cursor, Write};

const BASE: &str = "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?security=tls&sni=mask.example&fp=firefox&type=ws&path=%2Fedge&host=cdn.example&alpn=http%2F1.1";
fn zipped(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        zip.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

#[test]
fn mux_preserves_transport_and_tls_for_the_actual_core() {
    for suffix in [
        "&mux=true&muxConcurrency=8",
        "&mux=1&concurrency=8",
        "&mux=true",
    ] {
        let link = format!("{BASE}{suffix}");
        let parsed = parse_uri(&link).unwrap();
        assert!(parsed.engine == EngineKind::Xray);
        let outbound = parsed.outbound;
        assert_eq!(outbound["mux"], json!({"enabled":true,"concurrency":8}));
        assert_eq!(
            outbound["streamSettings"]["wsSettings"],
            json!({"path":"/edge","host":"cdn.example"})
        );
        let tls = &outbound["streamSettings"]["tlsSettings"];
        assert_eq!(tls["serverName"], "mask.example");
        assert_eq!(tls["alpn"], json!(["http/1.1"]));
        assert_eq!(tls["fingerprint"], "firefox");
        assert_eq!(tls["allowInsecure"], false);
        assert_eq!(catalog::read_input(&link).unwrap().profiles.len(), 1);
    }
    for suffix in [
        "&mux=true&allowInsecure=true",
        "&mux=true&muxConcurrency=8&concurrency=1",
        "&mux=true&muxConcurrency=x",
    ] {
        assert!(parse_uri(&format!("{BASE}{suffix}")).is_err());
    }
}

#[test]
fn future_protocol_field_and_unsafe_tls_are_inert_in_every_wrapper() {
    let unknown = format!("{BASE}&newTransportSetting=yes#Future");
    let insecure = format!("{BASE}&insecure=true#Unsafe");
    let foreign = "futurevpn://secret@future.example:443#Future2";
    let lines = format!("{BASE}#Selected\n{unknown}\n{insecure}\n{foreign}\n{BASE}#Selected");
    let encoded = STANDARD.encode(&lines);
    let json = json!({"configs":lines.lines().collect::<Vec<_>>()}).to_string();
    for data in [
        lines.as_bytes().to_vec(),
        encoded.into_bytes(),
        json.into_bytes(),
        zipped(&[("links.txt", lines.as_bytes())]),
    ] {
        let doc = catalog::read_bytes(&data).unwrap();
        assert_eq!(doc.profiles.len(), 1);
        assert_eq!(doc.unavailable.len(), 3);
        assert!(
            doc.unavailable
                .iter()
                .any(|u| u.input == unknown && u.name == "Future")
        );
        let mut state = Settings::default();
        state.apply_document(None, doc).unwrap();
        let saved = serde_json::to_vec(&state).unwrap();
        let read: Settings = serde_json::from_slice(&saved).unwrap();
        read.validate().unwrap();
        let sub = read.current().unwrap();
        assert_eq!(sub.selected_profile().unwrap().name, "Selected");
        assert_eq!(sub.profiles.len(), 1);
        assert_eq!(catalog::retry_local(sub).unwrap().unavailable.len(), 3);
    }
}

#[test]
fn core_rejection_isolated_from_working_siblings() {
    let bad = json!({"protocol":"vless","tag":"Bad","settings":{"vnext":[{"address":"edge.example","port":443,"users":[{"id":"a3ba7b44-3275-42e7-9a54-30aa2bde0437","encryption":"none"}]}]},
      "streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"tls.example"},"xhttpSettings":{"path":"/","extra":{"scMaxBufferedPosts":"invalid-number"}}}});
    let good_mux = format!("{BASE}&mux=true");
    let doc=catalog::read_input(&json!({"outbounds":[good_mux,bad,BASE,{"protocol":"futurevpn","tag":"Another","server":"test.example"}]}).to_string()).unwrap();
    assert_eq!(doc.profiles.len(), 2);
    assert_eq!(doc.profiles[0].uri, good_mux);
    assert_eq!(doc.profiles[1].uri, BASE);
    assert_eq!(doc.unavailable.len(), 2);
    assert!(
        doc.unavailable
            .iter()
            .any(|p| matches!(p.reason, eivro::subscription::UnavailableReason::Core))
    );
}

#[test]
fn all_unsupported_refresh_retains_selection_and_new_import_can_be_rechecked() {
    let mut state = Settings::default();
    state
        .apply_document(None, catalog::read_input(BASE).unwrap())
        .unwrap();
    let id = state.current().unwrap().id;
    state
        .apply_document(
            Some(id),
            catalog::read_input("newvpn://secret@future.example#Future").unwrap(),
        )
        .unwrap();
    let current = state.current().unwrap();
    assert!(current.using_previous);
    assert_eq!(current.selected_profile().unwrap().uri, BASE);
    assert_eq!(current.unavailable.len(), 1);
    state
        .apply_document(Some(id), catalog::read_input(BASE).unwrap())
        .unwrap();
    assert!(!state.current().unwrap().using_previous);
    assert!(state.current().unwrap().unavailable.is_empty());
    let mut local = Settings::default();
    local
        .apply_document(None, catalog::read_input("futurevpn://x#New").unwrap())
        .unwrap();
    assert!(local.selected_profile().is_none());
    // Simulate a client upgrade that now supports the stored input.
    local.current_mut().unwrap().unavailable[0].input = BASE.into();
    let doc = catalog::retry_local(local.current().unwrap()).unwrap();
    assert!(doc.unavailable.is_empty());
    assert_eq!(doc.profiles[0].name, "New");
}

#[test]
fn broken_archive_record_is_isolated_but_container_limits_still_fail() {
    let batch = catalog::read_bytes(&zipped(&[
        ("a.txt", BASE.as_bytes()),
        ("b.json", b"{damaged"),
    ]))
    .unwrap();
    assert_eq!((batch.profiles.len(), batch.unavailable.len()), (1, 1));
    assert!(catalog::read_bytes(&zipped(&[("../bad.txt", BASE.as_bytes())])).is_err());
    assert!(catalog::read_input("<html>login</html>").is_err());
    assert!(catalog::read_input("{bad-json").is_err());
    assert!(catalog::read_input(&vec!["futurevpn://x"; 257].join("\n")).is_err());
}

#[test]
fn opaque_configurations_stay_local_and_service_error_pages_do_not_become_profiles() {
    for text in [
        "[Interface]\nPrivateKey=synthetic\n[Peer]\nPublicKey=synthetic",
        "proxies:\n  - name: synthetic\n    type: futurevpn\n    server: example.org",
        "client\nremote vpn.example 443\nup /nonexistent/script",
    ] {
        let doc = catalog::read_input(text).unwrap();
        assert!(doc.profiles.is_empty());
        assert_eq!(doc.unavailable[0].input, text);
        let sub = doc.into_subscription(1);
        assert!(catalog::retry_local(&sub).unwrap().profiles.is_empty());
    }
    assert!(catalog::read_input(r#"{"error":"expired","code":403}"#).is_err());
    assert!(catalog::read_input(r#"["https://provider.example/token"]"#).is_err());
}

#[test]
#[cfg(unix)]
fn upgrading_protects_the_old_store_for_rollback() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("eivro-import-v7-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("settings.json");
    let previous = serde_json::to_vec(&Settings {
        schema: eivro::storage::SCHEMA - 1,
        ..Default::default()
    })
    .unwrap();
    std::fs::write(&file, &previous).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut settings = eivro::storage::load(&file).unwrap();
    settings
        .apply_document(
            None,
            catalog::read_input("futurevpn://secret@future.example").unwrap(),
        )
        .unwrap();
    eivro::storage::save(&file, &settings).unwrap();
    let backup = dir.join("settings-before-1.5.0.json");
    assert_eq!(std::fs::read(&backup).unwrap(), previous);
    assert_eq!(
        std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        eivro::storage::load(&file)
            .unwrap()
            .current()
            .unwrap()
            .unavailable
            .len(),
        1
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
