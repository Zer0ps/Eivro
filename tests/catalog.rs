use base64::{Engine, engine::general_purpose::STANDARD};
use eivro::{
    catalog::{self, Document, Metadata, UpdatePolicy},
    import::Profile,
    storage::Settings,
    subscription,
};
use serde_json::json;
use std::io::Write;
fn profile(name: &str, port: u16) -> Profile {
    Profile {
        name: name.into(),
        uri: format!("ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:{port}#{name}"),
    }
}
fn document() -> Document {
    Document {
        name: "Provider".into(),
        source: Some("https://provider.example/sub/secret".into()),
        profiles: vec![profile("A", 443), profile("B", 444)],
        metadata: Metadata::default(),
    }
}
fn vless_profile(name: &str, server: &str, annotation: &str) -> Profile {
    Profile {
        name: name.into(),
        uri: format!(
            "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@{server}:443?security=tls&type=tcp&sni=cover.example{annotation}#{name}"
        ),
    }
}
#[test]
fn metadata_survives_plain_base64_gzip_and_zip() {
    let text = format!(
        "#profile-title: base64:{}\n#profile-update-interval: 2\n#announce: base64:{}\n#subscription-userinfo: upload=10; download=20; total=100; expire=1800000000\n#support-url: https://support.example/help\n{}",
        STANDARD.encode("Провайдер"),
        STANDARD.encode("Первая строка\nВторая строка"),
        profile("A", 443).uri
    );
    let encoded = STANDARD.encode(&text);
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(encoded.as_bytes()).unwrap();
    let gzip = gzip.finish().unwrap();
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("subscription.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(text.as_bytes()).unwrap();
    let zip = zip.finish().unwrap().into_inner();
    for data in [text.as_bytes(), encoded.as_bytes(), &gzip, &zip] {
        let (profiles, metadata) = subscription::import_document(data).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(metadata.title, "Провайдер");
        assert_eq!(metadata.announcement, "Первая строка\nВторая строка");
        assert_eq!(metadata.interval_hours, Some(2));
        assert_eq!(metadata.download, Some(20));
        assert_eq!(metadata.expires, Some(1800000000));
        metadata.validate().unwrap();
    }
}
#[test]
fn metadata_cannot_introduce_commands_or_unbounded_refresh() {
    let mut m = Metadata::default();
    for interval in ["0", "-1", "0.5", "99999999", "abc"] {
        m.apply("profile-update-interval", interval);
        assert!(m.interval_hours.is_none());
    }
    for url in [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "http://example.com",
        "https://user:pass@example.com",
    ] {
        m.apply("support-url", url);
        assert!(m.support_url.is_none());
        assert!(catalog::source_url(url).is_err());
    }
    m.apply("custom-tunnel-config", "{\"log\":true}");
    m.apply("routing-enable", "0");
    assert_eq!(
        serde_json::to_value(m).unwrap(),
        serde_json::to_value(Metadata::default()).unwrap()
    );
}
#[test]
fn old_settings_keep_all_servers_selection_and_rules() {
    let mut settings:Settings=serde_json::from_value(json!({"schema":1,"profiles":[profile("A",443),profile("B",444)],"selected":1,"bypass":["*.example.test"],"mode":"tun","accent":[0,0,0]})).unwrap();
    settings.migrate().unwrap();
    assert_eq!(settings.schema, 4);
    assert_eq!(settings.subscriptions.len(), 1);
    assert_eq!(settings.selected_profile().unwrap().name, "B");
    assert!(settings.bypass.is_empty());
    assert_eq!(
        settings.routing_profiles[0].rules[0].target.value(),
        "*.example.test"
    );
    assert_eq!(settings.accent, [0, 0, 0]);
    assert!(settings.current().unwrap().source.is_none());
    assert!(settings.current().unwrap().interval().is_none());
    let encoded = serde_json::to_value(&settings).unwrap();
    assert!(encoded.get("profiles").is_none());
    assert!(encoded.get("selected").is_none());
    let mut reloaded: Settings = serde_json::from_value(encoded).unwrap();
    reloaded.migrate().unwrap();
    assert_eq!(reloaded.selected_profile().unwrap().name, "B");
}
#[test]
fn refreshing_only_replaces_its_group_and_preserves_selection() {
    let mut settings = Settings::default();
    settings.apply_document(None, document()).unwrap();
    settings.subscriptions[0].selected = 1;
    let mut other = document();
    other.source = Some("https://other.example/sub".into());
    settings.apply_document(None, other).unwrap();
    let mut updated = document();
    updated.profiles = vec![profile("B", 445), profile("A", 443)];
    settings.apply_document(Some(1), updated).unwrap();
    assert_eq!(settings.subscriptions.len(), 2);
    assert_eq!(
        settings.selected_profile().unwrap().uri,
        profile("B", 445).uri
    );
    assert_eq!(
        settings.subscriptions[1].profiles[1].uri,
        profile("B", 444).uri
    );
    settings.apply_document(None, document()).unwrap();
    assert_eq!(settings.subscriptions.len(), 2);
    assert_eq!(settings.selected_profile().unwrap().name, "B");
    let before = serde_json::to_string(&settings).unwrap();
    let mut invalid = document();
    invalid.profiles[0].uri = "bad".into();
    assert!(settings.apply_document(Some(1), invalid).is_err());
    assert_eq!(serde_json::to_string(&settings).unwrap(), before);
}
#[test]
fn removed_refresh_target_cannot_replace_a_reimported_source() {
    let mut settings = Settings::default();
    settings.apply_document(None, document()).unwrap();
    let removed_id = settings.subscriptions.remove(0).id;
    settings.apply_document(None, document()).unwrap();
    let current_id = settings.subscriptions[0].id;
    assert_ne!(current_id, removed_id);
    settings.subscriptions[0].selected = 1;
    settings.routing_profiles[0]
        .add_addresses("example.test", eivro::policy::Action::Direct)
        .unwrap();
    let before = serde_json::to_value(&settings).unwrap();
    let mut updated = document();
    updated.profiles = vec![profile("B", 445), profile("A", 443)];
    assert!(
        settings
            .apply_document(Some(removed_id), updated.clone())
            .is_err()
    );
    assert_eq!(serde_json::to_value(&settings).unwrap(), before);

    // A deliberate new import may still update the subscription with this source.
    settings.apply_document(None, updated).unwrap();
    assert_eq!(settings.subscriptions.len(), 1);
    assert_eq!(settings.subscriptions[0].id, current_id);
    assert_eq!(
        settings.selected_profile().unwrap().uri,
        profile("B", 445).uri
    );
    assert_eq!(
        settings.routing_profiles[0].rules[0].target.value(),
        "example.test"
    );
}
#[test]
fn annotations_and_reordering_preserve_selection_with_duplicate_names() {
    let mut original = document();
    original.profiles = ["a.example", "b.example", "c.example"]
        .map(|server| vless_profile("Shared", server, ""))
        .into();
    let mut sub = original.into_subscription(1);
    sub.selected = 1;
    let mut updated = document();
    updated.profiles = ["c.example", "a.example", "b.example"]
        .map(|server| vless_profile("Shared", server, "&x-durev-sni-change=true"))
        .into();
    sub.replace(updated, 123);
    assert_eq!(sub.selected, 2);
    assert_eq!(
        sub.selected_profile().unwrap().uri,
        vless_profile("Shared", "b.example", "&x-durev-sni-change=true").uri
    );
    assert_eq!(sub.refreshed_at, Some(123));
}
#[test]
fn refresh_selection_prefers_exact_uri_and_requires_a_unique_connection_match() {
    let selected = vless_profile("Chosen", "b.example", "");
    let mut original = document();
    original.profiles = vec![selected.clone()];
    let mut sub = original.into_subscription(1);
    let mut updated = document();
    updated.profiles = vec![
        vless_profile("Alias", "b.example", "&x-durev-sni-change=true"),
        selected,
    ];
    sub.replace(updated, 123);
    assert_eq!(sub.selected, 1);

    let mut ambiguous = document();
    ambiguous.profiles = vec![
        vless_profile("Alias", "b.example", "&x-durev-sni-change=false"),
        vless_profile("Chosen", "b.example", "&x-durev-sni-change=true"),
    ];
    sub.replace(ambiguous, 124);
    // Neither URI matches; equivalent endpoints are ambiguous, so the unique name wins.
    assert_eq!(sub.selected, 1);
}
#[test]
fn provider_interval_custom_interval_and_manual_are_distinct() {
    let mut sub = document().into_subscription(1);
    sub.refreshed_at = Some(100);
    assert!(sub.due_at().is_none());
    sub.metadata.interval_hours = Some(2);
    assert_eq!(sub.due_at(), Some(7300));
    sub.update = UpdatePolicy::EveryHours(3);
    assert_eq!(sub.due_at(), Some(10900));
    sub.update = UpdatePolicy::Manual;
    assert!(sub.due_at().is_none());
    sub.update = UpdatePolicy::EveryHours(1);
    sub.source = None;
    assert!(sub.due_at().is_none());
}
#[test]
fn migration_save_keeps_one_private_rollback_snapshot() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("eivro-migration-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("settings.json");
    let bytes = serde_json::to_vec(&json!({"schema":1,"profiles":[profile("A",443)],"selected":0}))
        .unwrap();
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut settings = eivro::storage::load(&path).unwrap();
    eivro::storage::save(&path, &settings).unwrap();
    let backup = dir.join("settings-before-alpha.json");
    assert_eq!(std::fs::read(&backup).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    settings.routing_profiles[0]
        .add_addresses("example.test", eivro::policy::Action::Direct)
        .unwrap();
    eivro::storage::save(&path, &settings).unwrap();
    assert_eq!(std::fs::read(&backup).unwrap(), bytes);
    std::fs::remove_dir_all(&dir).unwrap();
}
#[test]
fn comments_outside_base64_do_not_hide_the_payload() {
    let payload = STANDARD.encode(profile("A", 443).uri);
    let body =
        format!("#profile-title: Provider\n#support-url: https://support.example/\n{payload}");
    let (profiles, metadata) = subscription::import_document(body.as_bytes()).unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(metadata.title, "Provider");
}
