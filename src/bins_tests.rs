use super::{compile_initializer, hardens};
use std::path::Path;

#[test]
fn msvc_windows_is_hardened() {
    assert_eq!(hardens("windows", "msvc"), Ok(true));
}

#[test]
fn other_operating_systems_are_left_alone() {
    for (os, env) in [("linux", "gnu"), ("linux", "musl"), ("macos", ""), ("freebsd", "")] {
        assert_eq!(hardens(os, env), Ok(false), "{os}-{env}");
    }
}

/// Cygwin executables are PE files, loaded by the Windows loader like any other.
#[test]
fn cygwin_is_refused_with_the_reason() {
    for env in ["", "gnu"] {
        let message = hardens("cygwin", env).unwrap_err();
        assert!(
            message.contains("cygwin") && message.contains("DEPENDENTLOADFLAG"),
            "{env}: {message}"
        );
    }
}

/// Whatever made rustc fail, the message must be true, so it states the one known limit and not a cause.
#[test]
#[should_panic(
    expected = "compiling libsearch-guard's initializer for no-such-target failed (rustc's error is above). A target with no prebuilt `core` (tier 3, -Zbuild-std) is not supported."
)]
fn a_failed_initializer_compile_names_the_target_and_the_known_limit() {
    let dir = tempfile::tempdir().unwrap();
    compile_initializer("no-such-target", dir.path(), Path::new("rustc"));
}

#[test]
fn windows_targets_other_than_msvc_are_refused_with_the_reason() {
    for env in ["gnu", "gnullvm", ""] {
        let message = hardens("windows", env).unwrap_err();
        assert!(
            message.contains("only windows-msvc") && message.contains("DEPENDENTLOADFLAG"),
            "{env}: {message}"
        );
    }
}
