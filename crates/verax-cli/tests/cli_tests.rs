use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_verax"))
}

#[test]
fn test_cli_version() {
    let output = cli().arg("--version").output().unwrap();
    assert!(
        output.status.success(),
        "version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("verax"),
        "version output missing 'verax': {stdout}"
    );
}

#[test]
fn test_cli_help() {
    let output = cli().arg("--help").output().unwrap();
    assert!(
        output.status.success(),
        "help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Commands"),
        "help output missing 'Commands': {stdout}"
    );
}

#[test]
fn test_cli_sign_verify() {
    let dir = tempfile::TempDir::new().unwrap();
    let artifact = dir.path().join("test.txt");
    std::fs::write(&artifact, b"hello verax").unwrap();
    let axm_path = dir.path().join("test.axm");

    // sign
    let out = cli()
        .arg("sign")
        .arg(&artifact)
        .arg("--out")
        .arg(&axm_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(axm_path.exists(), "signed file not found: {axm_path:?}");

    // verify
    let out = cli().arg("verify").arg(&axm_path).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() || stderr.contains("PASS"),
        "verify failed: {}",
        stderr
    );
}

#[test]
fn test_cli_key_generate() {
    let dir = tempfile::TempDir::new().unwrap();
    let key_path = dir.path().join("mykey.key");
    let out = cli()
        .args(["key", "generate", "--out", &key_path.to_string_lossy()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "key generate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(key_path.exists(), "key file not found: {key_path:?}");
}

#[test]
fn test_cli_init() {
    let dir = tempfile::TempDir::new().unwrap();
    let out = cli().arg("init").current_dir(&dir).output().unwrap();
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.path().join(".verax").exists(), ".verax dir not created");
    assert!(
        dir.path().join(".verax/config.toml").exists(),
        "config.toml not created"
    );
}

#[test]
fn test_cli_hash() {
    let dir = tempfile::TempDir::new().unwrap();
    let artifact = dir.path().join("data.bin");
    std::fs::write(&artifact, b"some data to hash").unwrap();
    let out = cli()
        .args(["hash", &artifact.to_string_lossy()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "hash failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.is_empty(), "hash output was empty");
}
