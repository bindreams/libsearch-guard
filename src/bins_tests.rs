use super::{compile_initializer, hardens, plan, unicode, var_os};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

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

/// The failure message names the known limit, not a guessed cause.
#[test]
#[should_panic(
    expected = "compiling libsearch-guard's initializer for no-such-target failed (rustc's error is above). A target with no prebuilt `core` (tier 3, -Zbuild-std) is not supported."
)]
fn a_failed_initializer_compile_names_the_target_and_the_known_limit() {
    let dir = tempfile::tempdir().unwrap();
    let initializer = plan("windows", "msvc", dir.path()).unwrap().unwrap();
    compile_initializer("no-such-target", Path::new("rustc"), &initializer);
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

/// A value that is not valid Unicode, as Windows (unpaired surrogate) and Unix (invalid UTF-8) allow.
fn not_unicode() -> OsString {
    #[cfg(windows)]
    {
        std::os::windows::ffi::OsStringExt::from_wide(&[0x61, 0xD800, 0x62])
    }
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStringExt::from_vec(vec![b'a', 0xFF, b'b'])
    }
}

#[test]
#[should_panic(expected = "LIBSEARCH_GUARD_UNSET_FOR_TEST is not set; call `bins()` from a build script")]
fn an_unset_variable_says_it_is_not_set() {
    var_os("LIBSEARCH_GUARD_UNSET_FOR_TEST");
}

#[test]
#[should_panic(expected = "TARGET is not valid Unicode")]
fn a_variable_that_is_not_unicode_is_not_called_unset() {
    unicode("TARGET", not_unicode());
}

/// rustc takes only Unicode arguments and a link argument is a `cargo:` line, so a non-Unicode `OUT_DIR`, where the
/// source and the object go, is refused by the decision, before rustc runs.
#[test]
fn a_non_unicode_out_dir_is_refused_before_anything_is_compiled() {
    let out_dir = PathBuf::from(not_unicode());
    let message = plan("windows", "msvc", &out_dir).unwrap_err();
    assert!(
        message.contains("is not valid Unicode") && message.contains("use a target directory with a Unicode path"),
        "{message}"
    );
}

#[test]
fn a_non_unicode_out_dir_does_not_matter_where_nothing_is_compiled() {
    let out_dir = PathBuf::from(not_unicode());
    for (os, env) in [("linux", "gnu"), ("macos", ""), ("freebsd", "")] {
        assert!(matches!(plan(os, env, &out_dir), Ok(None)), "{os}-{env}");
    }
}

#[test]
fn a_target_that_cannot_be_hardened_is_refused_whatever_out_dir_is() {
    let message = plan("windows", "gnu", Path::new("out")).unwrap_err();
    assert!(message.contains("only windows-msvc"), "{message}");
}

#[test]
fn the_source_and_the_object_go_in_out_dir() {
    let initializer = plan("windows", "msvc", Path::new("out")).unwrap().unwrap();
    assert_eq!(Path::new(&initializer.source).parent(), Some(Path::new("out")));
    assert_eq!(Path::new(&initializer.object).parent(), Some(Path::new("out")));
    assert_ne!(initializer.source, initializer.object);
}
