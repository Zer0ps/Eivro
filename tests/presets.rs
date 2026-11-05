use eivro::{
    config::{self, ConnectRequest, Mode},
    policy::{Action, RoutingProfile},
    presets::{RuPreset, RuSet},
    storage::Settings,
};

fn request(set: RuSet) -> ConnectRequest {
    ConnectRequest {
        ru_preset: Some(RuPreset::new(set)),
        uri: "ss://chacha20-ietf-poly1305:synthetic@127.0.0.1:443".into(),
        bypass: vec![],
        port: 2080,
        bridge_port: None,
        probe_port: None,
        policies: vec![],
        kill_switch: false,
        connections: vec![],
    }
}

#[test]
fn profiles_are_opt_in_compact_and_migration_does_not_recreate_removed_profiles() {
    let defaults = Settings::default();
    assert_eq!(defaults.selected_routing, 0);
    assert!(defaults.routing_profiles[0].ru_preset.is_none());
    assert_eq!(defaults.routing_profiles.len(), 3);
    assert!(serde_json::to_vec(&defaults).unwrap().len() < 2048);
    let mut old = defaults.clone();
    old.schema = 4;
    old.routing_profiles = vec![RoutingProfile::default()];
    old.routing_profiles[0]
        .add_addresses("work.test", Action::Direct)
        .unwrap();
    old.migrate().unwrap();
    assert_eq!(old.selected_routing, 0);
    assert_eq!(old.routing_profiles[0].matches("work.test"), Action::Direct);
    assert_eq!(old.routing_profiles.len(), 3);
    old.routing_profiles.pop();
    old.migrate().unwrap();
    assert_eq!(old.routing_profiles.len(), 2);
}

#[test]
fn suffixes_exclusions_and_user_overrides_have_the_same_meaning() {
    let mut profile = RoutingProfile::ru(RuSet::Services);
    assert_eq!(profile.matches("I8.PHOTO.2GIS.COM."), Action::Direct);
    assert_eq!(profile.matches("not2gis.com"), Action::Proxy);
    assert_eq!(profile.matches("example.org"), Action::Proxy);
    profile.add_addresses("*.2gis.com", Action::Proxy).unwrap();
    assert_eq!(profile.matches("i8.photo.2gis.com"), Action::Proxy);
    assert_eq!(profile.matches("2gis.com"), Action::Direct);
    let preset = profile.ru_preset.as_mut().unwrap();
    assert!(preset.matches("0rub.beeline.ru"));
    preset.disabled.insert("0rub.beeline.ru".into());
    assert!(!preset.matches("0rub.beeline.ru"));
    assert!(!preset.matches("child.0rub.beeline.ru"));
    assert!(preset.matches("beeline.ru"));
    preset.disabled.insert("5.45.192.0/24".into());
    assert!(!preset.matches("5.45.192.1"));
    assert!(preset.matches("5.45.193.1"));
}

#[test]
fn migration_preserves_unicode_name_collisions_and_full_profile_catalogs() {
    let mut settings = Settings {
        schema: 4,
        routing_profiles: vec![RoutingProfile {
            name: "ru-direct · сервисы".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    settings.migrate().unwrap();
    assert_eq!(settings.routing_profiles[0].name, "ru-direct · сервисы");
    assert_eq!(settings.routing_profiles[1].name, "RU-DIRECT · Сервисы (2)");
    let profiles: Vec<_> = (0..24)
        .map(|i| RoutingProfile {
            name: format!("User {i}"),
            ..Default::default()
        })
        .collect();
    let mut full = Settings {
        schema: 4,
        routing_profiles: profiles.clone(),
        selected_routing: 23,
        ..Default::default()
    };
    full.migrate().unwrap();
    assert_eq!(full.routing_profiles, profiles);
    assert_eq!(full.selected_routing, 23);
}

#[test]
fn full_tier_is_distinct_and_empty_or_disabled_sets_never_match_everything() {
    assert!(!RuPreset::new(RuSet::Services).matches("2.56.24.1"));
    assert!(RuPreset::new(RuSet::AllNetworks).matches("2.56.24.1"));
    let mut preset = RuPreset::new(RuSet::AllNetworks);
    preset.disabled = preset
        .set
        .entries()
        .map(|entry| entry.value.to_owned())
        .collect();
    assert!(preset.headless_rules().is_empty());
    assert!(!preset.matches("2gis.com"));
    preset.enabled = false;
    assert!(!preset.has_networks());
    assert!(preset.domain_matcher().is_none());
}

#[test]
fn full_user_exclusion_list_fits_the_bounded_helper_request() {
    let mut req = request(RuSet::AllNetworks);
    let preset = req.ru_preset.as_mut().unwrap();
    preset.disabled = preset.set.entries().map(|e| e.value.to_owned()).collect();
    preset.validate().unwrap();
    assert!(serde_json::to_vec(&req).unwrap().len() + 1024 < eivro::process::MAX_REQUEST);
}

#[test]
fn both_tiers_and_nested_exclusions_pass_the_real_core_parser() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    for set in RuSet::ALL {
        let mut req = request(set);
        req.ru_preset
            .as_mut()
            .unwrap()
            .disabled
            .extend(["0rub.beeline.ru".into(), "5.45.192.0/24".into()]);
        for mode in [Mode::Proxy, Mode::Tun] {
            let cfg = config::generate(&req, mode).unwrap();
            #[cfg(target_os = "linux")]
            let cfg = {
                let mut cfg = cfg;
                if mode == Mode::Tun {
                    eivro::domain_dns::configure(&mut cfg, &req).unwrap();
                }
                cfg
            };
            let data = cfg.to_string();
            #[cfg(windows)]
            let input = "stdin";
            #[cfg(unix)]
            let input = "/dev/stdin";
            let mut child = Command::new(eivro::process::core_path().unwrap())
                .args(["check", "-c", input])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(data.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

#[test]
#[cfg(unix)]
fn old_settings_are_backed_up_before_saving_presets() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let dir = std::env::temp_dir().join(format!("eivro-schema5-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("settings.json");
    let old = Settings {
        schema: 4,
        routing_profiles: vec![RoutingProfile::default()],
        ..Settings::default()
    };
    let original = serde_json::to_vec(&old).unwrap();
    fs::write(&path, &original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let migrated = eivro::storage::load(&path).unwrap();
    eivro::storage::save(&path, &migrated).unwrap();
    let backup = dir.join("settings-before-1.3.2.json");
    assert_eq!(fs::read(&backup).unwrap(), original);
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_dir_all(dir).unwrap();
}
