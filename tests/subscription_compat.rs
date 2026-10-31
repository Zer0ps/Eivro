use base64::{Engine, engine::general_purpose::STANDARD};
use eivro::{import::parse_uri, process, subscription};
use serde_json::json;
use std::io::{Cursor, Write};

fn link(transport: &str) -> String {
    let protection = if transport == "ws" {
        "security=tls&host=mask.example&path=%2Fws".to_owned()
    } else {
        format!(
            "security=reality&pbk={}&sid=aabbccdd",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1; 32])
        )
    };
    format!(
        "vless://a3ba7b44-3275-42e7-9a54-30aa2bde0437@edge.example:443?{protection}&type={transport}&sni=mask.example&fp=chrome{}",
        if transport == "xhttp" {
            "&mode=stream-one&path=%2Fstream"
        } else {
            ""
        }
    )
}

fn zip(data: &[u8]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("subscription.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(data).unwrap();
    zip.finish().unwrap().into_inner()
}

#[test]
fn provider_sni_hint_preserves_the_explicit_connection_configuration() {
    for transport in ["tcp", "xhttp", "ws"] {
        let base = link(transport);
        let expected = parse_uri(&base).unwrap();
        for flag in ["true", "false", "1", "0"] {
            let uri = format!("{base}&x-durev-sni-change={flag}&x-durev-block=test&x-durev-prio=1");
            let actual = parse_uri(&uri).unwrap();
            assert_eq!(actual.outbound, expected.outbound);
            assert!(actual.engine == expected.engine);
            assert_eq!(actual.host, expected.host);
            assert!(!actual.outbound.to_string().contains("x-durev"));
        }
    }
}

#[test]
fn vendor_hint_does_not_hide_unsafe_conflicting_or_unknown_options() {
    let base = link("xhttp");
    for suffix in [
        "&x-durev-sni-change=maybe",
        "&x-durev-sni-change=",
        "&x-durev-sni-change=true&x-durev-sni-change=false",
        "&x-durev-sni-change=true&allowInsecure=true",
        "&x-durev-sni-change=true&insecure=1",
        "&x-durev-sni-change=true&peer=different.example",
        "&x-durev-sni-change=true&%73ni=mask.example",
        "&x-durev-unknown-transport=1",
        "&unknown_tls_override=1",
    ] {
        assert!(parse_uri(&format!("{base}{suffix}")).is_err(), "{suffix}");
    }
    let no_sni = base.replace("&sni=mask.example", "");
    assert!(parse_uri(&format!("{no_sni}&x-durev-sni-change=true")).is_err());
    assert!(parse_uri(&format!("{no_sni}&x-durev-sni-change=false")).is_ok());
    assert!(parse_uri(&format!("{no_sni}&peer=mask.example&x-durev-sni-change=1")).is_ok());
}

#[test]
fn provider_hint_imports_in_plain_base64_json_and_archives_and_passes_cores() {
    let uri = format!("{}&x-durev-sni-change=true", link("xhttp"));
    let encoded = STANDARD.encode(&uri);
    let json = serde_json::to_vec(&vec![&uri]).unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&json).unwrap();
    for data in [
        uri.as_bytes().to_vec(),
        encoded.into_bytes(),
        json,
        zip(uri.as_bytes()),
        gzip.finish().unwrap(),
    ] {
        let profiles = subscription::import_bytes(&data).unwrap();
        assert_eq!(profiles.len(), 1);
        process::validate_profiles(&profiles).unwrap();
    }
}

#[test]
fn decoded_bom_comments_and_json_keep_metadata_and_endpoints() {
    let uri = format!("{}&x-durev-sni-change=true", link("xhttp"));
    let text = format!("\u{feff}#profile-title: Provider\n{}", json!(vec![uri]));
    let encoded = STANDARD.encode(&text);
    let double_encoded = STANDARD.encode(&encoded);
    for data in [
        text.as_bytes(),
        encoded.as_bytes(),
        double_encoded.as_bytes(),
        &zip(encoded.as_bytes()),
    ] {
        let (profiles, metadata) = subscription::import_document(data).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(metadata.title, "Provider");
    }
}

#[test]
fn unknown_query_keys_are_not_echoed_into_ui_errors() {
    for secret in [
        "private-token-without-value",
        "https%3A%2F%2Fprovider.example%2Fprivate-token",
    ] {
        let error = parse_uri(&format!("{}&{secret}", link("tcp")))
            .err()
            .unwrap();
        assert!(error.contains("неподдерживаемый параметр"));
        assert!(!error.contains("private-token"));
        assert!(!error.contains("provider.example"));
    }
}

#[test]
fn empty_and_html_responses_have_useful_secret_free_errors() {
    for data in [b"".as_slice(), b"#profile-title: Private provider\n"] {
        let error = subscription::import_bytes(data).err().unwrap();
        assert!(error.contains("пустую подписку"));
        assert!(!error.contains("Private provider"));
    }
    let html = "<!DOCTYPE html><html>private-token</html>";
    for data in [html.as_bytes().to_vec(), STANDARD.encode(html).into_bytes()] {
        let error = subscription::import_bytes(&data).err().unwrap();
        assert!(error.contains("HTML/XML"));
        assert!(!error.contains("private-token"));
    }
}
