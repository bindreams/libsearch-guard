use super::{compile_initializer, hardens, link_arg_path, unicode, var_os};
use std::ffi::OsString;
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

/// The failure message names the known limit, not a guessed cause.
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

#[test]
#[should_panic(expected = "is not valid Unicode, and a link argument must be")]
fn a_link_argument_path_that_is_not_unicode_is_refused() {
    let dir = std::path::PathBuf::from(not_unicode());
    link_arg_path(&dir.join("initializer.obj"));
}

#[test]
fn a_unicode_link_argument_path_is_passed_through() {
    assert_eq!(link_arg_path(Path::new("out/initializer.obj")), "out/initializer.obj");
}
