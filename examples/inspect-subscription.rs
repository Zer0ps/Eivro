//! Reads subscription bytes or an HTTPS URL from stdin; prints only compatibility counts.
use std::io::Read;
fn main() {
    eivro::privacy::harden().expect("Cannot disable crash dumps");
    let mut data = Vec::new();
    std::io::stdin()
        .take(eivro::MAX_IMPORT as u64 + 1)
        .read_to_end(&mut data)
        .unwrap();
    let result = match std::str::from_utf8(&data) {
        Ok(text) if text.trim().starts_with("https://") => {
            // Follow the same metadata and core validation path as a UI refresh.
            eivro::catalog::read_input(text.trim()).map(|document| document.profiles)
        }
        _ => eivro::subscription::import_bytes(&data),
    };
    match result {
        Ok(profiles) => {
            if std::env::args().any(|arg| arg == "--check")
                && let Err(error) = eivro::process::validate_profiles(&profiles)
            {
                println!("Core validation rejected: {error}");
                std::process::exit(1);
            }
            let mut counts = std::collections::BTreeMap::new();
            for p in &profiles {
                let parsed = eivro::import::parse_uri(&p.uri).unwrap();
                *counts.entry(parsed.protocol).or_insert(0usize) += 1;
            }
            println!("Imported {} profiles: {:?}", profiles.len(), counts);
        }
        Err(e) => {
            println!("Import rejected: {e}");
            std::process::exit(1);
        }
    }
}
