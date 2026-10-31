use eivro::{import::parse_uri, subscription::import_bytes};
use serde_json::json;
use std::io::{Cursor, Write};

fn xray() -> serde_json::Value {
    json!({"remarks":"Test endpoint","log":{"loglevel":"debug","access":"/tmp/not-allowed"},"routing":{"rules":[{"outboundTag":"direct"}]},"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"a3ba7b44-3275-42e7-9a54-30aa2bde0437","encryption":"none","flow":""}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":false}}},{"protocol":"freedom","tag":"direct"}]})
}
fn singbox() -> serde_json::Value {
    json!({"outbounds":[{"type":"selector","tag":"choose","outbounds":["one"]},{"type":"trojan","tag":"one","server":"example.com","server_port":443,"password":"test:p@ss/word","tls":{"enabled":true,"server_name":"example.com","insecure":false}},{"type":"direct","tag":"direct"}]})
}
fn zip(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        zip.start_file(
            *name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

#[test]
fn xray_and_singbox_endpoints_are_imported_without_provider_policies() {
    let profiles = import_bytes(&serde_json::to_vec(&json!([xray(), singbox()])).unwrap()).unwrap();
    assert_eq!(profiles.len(), 2);
    assert_eq!(profiles[0].name, "Test endpoint");
    let parsed = parse_uri(&profiles[1].uri).unwrap();
    assert_eq!(parsed.outbound["password"], "test:p@ss/word");
    for p in profiles {
        let c = eivro::config::generate(
            &eivro::config::ConnectRequest {
                connections: vec![],
                probe_port: None,
                policies: vec![],
                kill_switch: false,
                bridge_port: if parse_uri(&p.uri).unwrap().engine == eivro::import::EngineKind::Xray
                {
                    Some(2081)
                } else {
                    None
                },
                uri: p.uri,
                bypass: vec![],
                port: 2080,
            },
            eivro::config::Mode::Local,
        )
        .unwrap();
        assert_eq!(c["log"], json!({"disabled":true}));
        assert_eq!(c["route"]["final"], "proxy");
        assert!(!c.to_string().contains("not-allowed"));
    }
}

#[test]
fn zip_gzip_and_tar_are_detected_by_bytes() {
    let data = serde_json::to_vec(&xray()).unwrap();
    let archive = zip(&[
        ("nested/server.json", data.clone()),
        ("README.txt", b"Not a configuration".to_vec()),
    ]);
    assert_eq!(import_bytes(&archive).unwrap().len(), 1);
    assert_eq!(
        import_bytes(&zip(&[("renamed.txt", archive)]))
            .unwrap()
            .len(),
        1
    );
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&data).unwrap();
    let gzip = gz.finish().unwrap();
    assert_eq!(import_bytes(&gzip).unwrap().len(), 1);
    assert_eq!(import_bytes(&zip(&[("renamed", gzip)])).unwrap().len(), 1);
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, "profile.json", data.as_slice())
        .unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar.into_inner().unwrap()).unwrap();
    assert_eq!(import_bytes(&gz.finish().unwrap()).unwrap().len(), 1);
}

#[test]
fn archive_wrapped_config_errors_do_not_drop_servers() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let invalid = "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?security=tls&type=tcp&mux=true#Unsupported";
    let commented = format!("#profile-title: Provider\n{invalid}");
    let corrupt_utf8 = [invalid.replace("&mux=true", "").as_bytes(), &[0xff]].concat();
    let payloads = [
        format!("\u{feff}{invalid}"),
        commented.clone(),
        format!("\u{feff}{commented}"),
        STANDARD.encode(invalid),
        STANDARD.encode(&commented),
        format!(
            "\u{feff}#profile-title: Provider\n{}",
            STANDARD.encode(invalid)
        ),
        STANDARD.encode(STANDARD.encode(invalid)),
        "\u{feff}#profile-title: Provider\n{invalid json".into(),
        STANDARD.encode("#profile-title: Provider\n{invalid json"),
        "eivro-xray://invalid".into(),
    ];
    for name in ["servers.txt", "servers"] {
        for payload in &payloads {
            let archive = zip(&[
                ("valid.json", serde_json::to_vec(&xray()).unwrap()),
                (name, payload.as_bytes().to_vec()),
            ]);
            assert!(
                import_bytes(&archive).is_err(),
                "invalid {name} was skipped"
            );
        }
        for payload in [
            corrupt_utf8.clone(),
            STANDARD.encode(&corrupt_utf8).into_bytes(),
            STANDARD.encode(STANDARD.encode(&corrupt_utf8)).into_bytes(),
            vec![0x1f, 0x8b, 0],
        ] {
            assert!(import_bytes(&payload).is_err());
            let archive = zip(&[
                ("valid.json", serde_json::to_vec(&xray()).unwrap()),
                (name, payload),
            ]);
            assert!(
                import_bytes(&archive).is_err(),
                "corrupt {name} was skipped"
            );
        }
    }
}

#[test]
fn archive_base64_depth_limit_does_not_drop_servers() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let uri =
        "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?security=tls&type=tcp#Test";
    let mut wrapped = STANDARD.encode(STANDARD.encode(uri));
    for _ in 3..=5 {
        wrapped = STANDARD.encode(&wrapped);
        for name in ["servers.txt", "servers"] {
            let archive = zip(&[
                ("valid.json", serde_json::to_vec(&xray()).unwrap()),
                (name, wrapped.as_bytes().to_vec()),
            ]);
            let error = import_bytes(&archive)
                .err()
                .expect("nested Base64 was skipped");
            assert_eq!(error, "Слишком много слоёв Base64 в подписке.");
        }
    }
}

#[test]
fn uppercase_uri_scheme_imports_from_plain_base64_and_archives() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let uri =
        "VLESS://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?security=tls&type=tcp#Test";
    let expected = parse_uri(uri).unwrap().outbound;
    for payload in [uri.to_owned(), STANDARD.encode(uri)] {
        for body in [
            payload.as_bytes().to_vec(),
            zip(&[
                ("valid.json", serde_json::to_vec(&xray()).unwrap()),
                ("servers.txt", payload.as_bytes().to_vec()),
            ]),
        ] {
            let profiles = import_bytes(&body).unwrap();
            let imported = profiles
                .iter()
                .find(|p| p.uri == uri)
                .expect("URI was skipped");
            assert_eq!(parse_uri(&imported.uri).unwrap().outbound, expected);
        }
    }
}

#[test]
fn archive_wrapped_configs_import_and_readme_metadata_is_ignored() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let uri =
        "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?security=tls&type=tcp#Test";
    let commented = format!("\u{feff}#profile-title: Provider\n{uri}");
    for payload in [
        commented,
        STANDARD.encode(format!("#profile-title: Provider\n{uri}")),
        STANDARD.encode(STANDARD.encode(uri)),
    ] {
        let archive = zip(&[("servers.txt", payload.into_bytes())]);
        let profiles = import_bytes(&archive).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].uri, uri);
    }
    let native = eivro::xray::profile(&xray()["outbounds"][0]).unwrap();
    let archive = zip(&[("native.txt", native.uri.as_bytes().to_vec())]);
    assert_eq!(import_bytes(&archive).unwrap()[0].uri, native.uri);
    let archive = zip(&[
        ("valid.json", serde_json::to_vec(&xray()).unwrap()),
        (
            "README.txt",
            b"\xef\xbb\xbf#profile-title: Documentation\nUsage instructions for this archive."
                .to_vec(),
        ),
        (
            "LICENSE",
            STANDARD.encode("Not a configuration").into_bytes(),
        ),
        ("EMPTY.txt", Vec::new()),
        ("NOTES", b"#profile-title: Documentation".to_vec()),
    ]);
    let (profiles, metadata) = eivro::subscription::import_document(&archive).unwrap();
    assert_eq!(profiles.len(), 1);
    assert!(metadata.title.is_empty());
}

#[test]
fn archives_enforce_paths_sizes_depth_and_file_count() {
    let data = serde_json::to_vec(&xray()).unwrap();
    assert!(import_bytes(&zip(&[("../../profile.json", data.clone())])).is_err());
    assert!(import_bytes(&zip(&[("profile.json", vec![b' '; eivro::MAX_IMPORT + 1])])).is_err());
    let many: Vec<_> = (0..33)
        .map(|i| (format!("{i}.json"), data.clone()))
        .collect();
    let refs: Vec<_> = many.iter().map(|(n, d)| (n.as_str(), d.clone())).collect();
    assert!(import_bytes(&zip(&refs)).is_err());
    let mut nested = data;
    for _ in 0..5 {
        nested = zip(&[("nested.zip", nested)]);
    }
    assert!(import_bytes(&nested).is_err());
}

#[test]
fn unsupported_json_features_are_not_silently_downgraded() {
    let mut x = xray();
    x["outbounds"][0]["streamSettings"]["network"] = json!("xhttp");
    assert!(import_bytes(x.to_string().as_bytes()).is_err());
    let mut x = xray();
    x["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] = json!(true);
    assert!(import_bytes(x.to_string().as_bytes()).is_err());
    let mut s = singbox();
    s["outbounds"][1]["tls"]["certificate_path"] = json!("/etc/shadow");
    assert!(import_bytes(s.to_string().as_bytes()).is_err());
    assert!(import_bytes(b"<html>login page</html>").is_err());
}

#[test]
fn concurrency_links_import_from_plain_base64_json_and_archives() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let text = "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?security=tls&type=tcp&concurrency=8#Test";
    let base64 = STANDARD.encode(text);
    let json = serde_json::to_vec(&vec![text]).unwrap();
    let zip = zip(&[("servers.txt", base64.as_bytes().to_vec())]);
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&json).unwrap();
    let gzip = gzip.finish().unwrap();
    for data in [text.as_bytes(), base64.as_bytes(), &json, &zip, &gzip] {
        let profiles = import_bytes(data).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "Test");
        let out = parse_uri(&profiles[0].uri).unwrap().outbound;
        assert_eq!(out["tls"]["insecure"], false);
        assert!(out.get("multiplex").is_none());
    }
    let invalid = format!(
        "{text}\n{}",
        text.replace("concurrency=8", "mux=true&concurrency=8")
    );
    assert!(import_bytes(invalid.as_bytes()).is_err());
}
