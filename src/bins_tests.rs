use super::{compile_initializer, hardens, initializer_command, plan, unicode, var_os};
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

/// The assembly rustc writes for the initializer on `target`, which needs that target's `core`: a test that
/// cannot compile for it fails, naming it. `LIBSEARCH_GUARD_SKIP_CROSS_TARGET_TESTS=1` is the explicit opt-out.
fn initializer_assembly(target: &str) -> Option<String> {
    if std::env::var_os("LIBSEARCH_GUARD_SKIP_CROSS_TARGET_TESTS").is_some() {
        eprintln!("skipped for {target}: LIBSEARCH_GUARD_SKIP_CROSS_TARGET_TESTS is set");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("pre_main.rs");
    let assembly = dir.path().join("pre_main.s");
    std::fs::write(&source, super::INITIALIZER).unwrap();
    // The command line `bins()` compiles with, so the trap checked is the one that is linked: only `--emit` differs.
    let output = initializer_command(
        Path::new("rustc"),
        target,
        "asm",
        source.to_str().unwrap(),
        assembly.to_str().unwrap(),
    )
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "cannot compile the initializer for {target}: install it with `rustup target add {target}`, or set LIBSEARCH_GUARD_SKIP_CROSS_TARGET_TESTS=1 to skip these tests:
{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(std::fs::read_to_string(assembly).unwrap())
}

/// Where `TerminateProcess` has failed, the initializer must not return to the CRT: every Windows MSVC
/// architecture with a fast-fail trap ends in it, not in a loop.
#[test]
fn the_initializer_ends_in_a_fast_fail_trap_on_every_architecture_that_has_one() {
    for (target, trap) in [
        ("x86_64-pc-windows-msvc", "int	$41"),
        ("i686-pc-windows-msvc", "int	$41"),
        ("aarch64-pc-windows-msvc", "brk	#0xf003"),
        ("arm64ec-pc-windows-msvc", "brk	#0xf003"),
    ] {
        let Some(assembly) = initializer_assembly(target) else {
            continue;
        };
        assert!(
            assembly.contains(trap),
            "{target}: no {trap:?} in
{assembly}"
        );
    }
}

/// The object `bins()` links and the assembly the trap test reads come from one command line: only `--emit` differs.
#[test]
fn the_object_and_the_assembly_are_compiled_with_the_same_flags() {
    let args = |emit| {
        initializer_command(Path::new("rustc"), "x86_64-pc-windows-msvc", emit, "in.rs", "out")
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    };
    let (object, assembly) = (args("obj"), args("asm"));
    let differing: Vec<_> = object.iter().zip(&assembly).filter(|(a, b)| a != b).collect();
    assert_eq!(object.len(), assembly.len());
    assert_eq!(differing, [(&"--emit=obj".to_owned(), &"--emit=asm".to_owned())]);
}
