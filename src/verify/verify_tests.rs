use super::crafted::{elf, DT_RUNPATH};
use super::{verify, VerifyError};

#[test]
fn display_lists_every_violation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bin");
    std::fs::write(&path, elf(&[(DT_RUNPATH, "$ORIGIN:lib")])).unwrap();
    let message = verify(&path).unwrap_err().to_string();
    assert!(message.starts_with("2 library-search violation(s):"), "{message}");
    assert!(message.contains("$ORIGIN") && message.contains("lib"), "{message}");
}

#[test]
fn a_missing_file_is_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(verify(dir.path().join("absent")), Err(VerifyError::Io(_))));
}

#[test]
fn a_file_that_is_not_an_executable_is_unreadable_not_clean() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.txt");
    std::fs::write(&path, b"hello").unwrap();
    assert!(matches!(verify(&path), Err(VerifyError::Unreadable { .. })));
}
