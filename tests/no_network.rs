//! Creating an identity, a device certificate, a contact card, an invite or a safety number needs no
//! network: no source file of the crate names a socket, a resolver or an HTTP client, and the crate
//! reads no clock (the caller passes `now`). A scan that read no file fails, so an empty or moved
//! `src/` is not read as "no network".

use std::fs;
use std::path::Path;

/// Names a network call or a clock read would need
const FORBIDDEN: &[&str] = &[
    "std::net",
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "ToSocketAddrs",
    "reqwest",
    "ureq",
    "hyper",
    "tokio::net",
    "SystemTime::now",
    "Instant::now",
];

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_source_file_names_a_network_call_or_a_clock() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut scanned = 0;
    let mut found = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap();
        scanned += 1;
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for name in FORBIDDEN {
                if code.contains(name) {
                    found.push(format!("{}:{}: {name}", f.display(), n + 1));
                }
            }
        }
    }
    assert!(scanned >= 20, "scanned {scanned} files under src/");
    assert!(
        files.iter().any(|f| f.ends_with("contact_card.rs"))
            && files.iter().any(|f| f.ends_with("invite.rs"))
            && files.iter().any(|f| f.ends_with("safety_number.rs")),
        "the new modules are among the scanned files"
    );
    assert!(found.is_empty(), "network or clock use: {found:#?}");
}

#[test]
fn no_dependency_is_a_network_crate() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let deps: Vec<&str> = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("a [dependencies] table")
        .lines()
        .take_while(|l| !l.starts_with('['))
        .filter(|l| !l.trim_start().starts_with('#') && l.contains('='))
        .filter_map(|l| l.split('=').next().map(str::trim))
        .collect();
    assert!(!deps.is_empty(), "read no dependency");
    for name in ["reqwest", "ureq", "hyper", "tokio", "async-std", "surf", "isahc"] {
        assert!(!deps.contains(&name), "{name} is a dependency");
    }
}
