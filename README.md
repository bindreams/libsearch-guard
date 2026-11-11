# libsearch-guard

Stops a Windows executable from loading DLLs that someone dropped next to it, with one line in `build.rs`. Also checks Windows, Linux and macOS binaries for the same class of problem.

## The problem

Windows looks in an executable's own folder first, both for the DLLs in its import table (including `vcruntime140.dll`, which is not a KnownDLL) and for `LoadLibrary` calls made without flags, including those inside system DLLs such as shell32. Whoever can add a file to that folder runs code as the program.

Linux and macOS search the executable's folder only when the binary asks for it: `$ORIGIN` in RPATH/RUNPATH, or `@executable_path`, `@loader_path` or `@rpath` in Mach-O load commands.

## Use

```toml
[build-dependencies]
libsearch-guard = "0.1"

[dev-dependencies]
libsearch-guard = "0.1"  # only for `verify`
```

```rust
// build.rs
fn main() {
    libsearch_guard::bins();
}
```

That is all. Every `[[bin]]` of the package is hardened, including the bin's own unit-test and bench harness. Its library, integration tests, examples and `cdylib`s are not. Call `bins()` only from a package that has a `[[bin]]`: cargo rejects the link arguments otherwise.

On `windows` + `msvc` targets every `[[bin]]` gets:

1. The C startup code and the VC runtime linked statically, so there is no `vcruntime140.dll` import. The Universal CRT stays dynamic, unless the build already sets `-C target-feature=+crt-static`: then the whole CRT, the Universal CRT included, is static and these arguments are skipped. (The link arguments are those of the [`static_vcruntime`](https://crates.io/crates/static_vcruntime) crate, which cannot limit them to bins.)
2. `/DEPENDENTLOADFLAG:0x800` (`LOAD_LIBRARY_SEARCH_SYSTEM32`), so import-table loads search System32 only.
3. A `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` call before `main`, so `LoadLibrary` calls without flags search System32 only. If the call fails, the process writes the error to stderr and terminates before `main`.

The call in item 3 comes from a tiny `#![no_std]` object that `bins()` compiles with the build's own `rustc` into `OUT_DIR` and hands to the linker for the bins. It needs no C compiler and adds no code or dependency to the consumer's crates.

On targets that are not Windows, `bins()` does nothing: the loader searches the executable's folder only when the binary asks, and `verify` checks that it has not. Other Windows targets and Cygwin are refused: see Platform notes.

## Loading a sidecar DLL

A hardened executable that ships a DLL must load it explicitly:

- A sidecar that imports `vcruntime140.dll` loads with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`, and only where the Visual C++ redistributable is installed: that is what puts `vcruntime140.dll` in System32. The flags also govern the DLL's own dependencies, and the hardened executable has not loaded `vcruntime140.dll` for it. Where the redistributable may be missing, ship the sidecar static-CRT instead.
- A sidecar that is static-CRT and has no other imports loads with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` alone.

## Verify

```rust
#[test]
fn the_binary_is_hardened() {
    libsearch_guard::verify(env!("CARGO_BIN_EXE_mytool")).unwrap();
}
```

`verify(path)` reads the file and reports every violation it finds, not only the first:

| Format | A violation is                                                                                                                                                                                                                                                                                                |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PE     | `DependentLoadFlags` without 0x800; an import, or delay-load import, of a Visual C++ redistributable DLL: `vcruntime*`, `msvcp<n>*`, `msvcr<n>*`, `atl<n>*`, `concrt*`, `vcomp*`, `vccorlib*`, `vcamp*`, `mfc*`, `ucrtbased*` (`<n>` is a version digit: `msvcp_win`, `msvcrt` and `atl` are part of Windows) |
| ELF    | an RPATH or RUNPATH element that is `$ORIGIN`-based or relative (every element must be absolute); a `DT_NEEDED` that contains a `/` but does not start with one; a `PT_INTERP` that does not start with `/`                                                                                                   |
| Mach-O | any `LC_RPATH`; a dylib load command that is `@executable_path`-, `@loader_path`- or `@rpath`-based or relative; an `LC_DYLD_ENVIRONMENT` that puts such a directory on a `DYLD_*_PATH` list                                                                                                                  |

ELF files are read through their `PT_DYNAMIC` segment, as the loader reads them, so a binary without section headers is checked too. A file it cannot read as one of these formats is an error, not a pass. Universal Mach-O binaries are checked slice by slice.

## Platform notes

- **Windows targets other than MSVC** (`windows-gnu`, `windows-gnullvm`) **and Cygwin** (`target_os = "cygwin"`, whose executables are PE files loaded by the Windows loader): `bins()` fails the build. GNU ld has no `DEPENDENTLOADFLAG`, and the loader on those targets still searches the executable's folder, so the crate refuses rather than build a bin that looks hardened and is not. There is no switch to skip it.
- **MSVC targets without a prebuilt `core`** (tier 3 targets, `-Zbuild-std`): `bins()` fails the build. The initializer is compiled with the build's own `rustc` against the target's prebuilt `core`.
- **`+crt-static` passed only to the final crate**: `bins()` detects `+crt-static` through the target features cargo reports to the build script, which `RUSTFLAGS` and the target config set. `cargo rustc -- -C target-feature=+crt-static` reaches the final crate only and is not seen: the static-CRT link arguments are then emitted and make the Universal CRT dynamic.
- The library itself is not hardened: it ships no initializer and links no runtime tricks, so depending on it for `verify` changes nothing about the tests that use it.

## License

Apache-2.0.
