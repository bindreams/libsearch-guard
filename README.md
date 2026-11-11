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
3. A `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` call before `main`, so `LoadLibrary` calls without flags search System32 only. It runs in the `.CRT$XIAB` slot, which the CRT runs before every `.CRT$XC*` initializer: C++ static constructors and `ctor`-style crates, in the bin or in any dependency, come after it. If the call fails, the process writes the error to stderr (or, where there is no usable stderr, to the debugger with `OutputDebugStringA`) and terminates before `main`. A fast-fail trap follows the termination, so the process never reaches `main` unhardened.

The call in item 3 comes from a tiny `#![no_std]` object that `bins()` compiles with the build's own `rustc` into `OUT_DIR` and hands to the linker for the bins. It needs no C compiler and adds no code or dependency to the consumer's crates.

Code that runs before the guard: TLS callbacks (`.CRT$XL*`), which the loader calls before the CRT starts; the CRT's own start-up code and the initializers it registers in `.CRT$XIAA`; and the loader's resolution of the import table, which `/DEPENDENTLOADFLAG` (item 2) covers. A TLS callback that calls `LoadLibrary` without flags is not protected.

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

| Format | A violation is                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| PE     | `DependentLoadFlags` without 0x800; an import, or delay-load import, of a Visual C++ redistributable DLL: `vcruntime<n>`, `msvcp<n>`, `msvcr<n>`, `concrt<n>`, `vcomp<n>`, `vccorlib<n>`, `vcamp<n>`, `mfc<n>`, `mfcm<n>` or `atl<n>` (`<n>` is the version digits, with the `_<n>`, `d`, `u` and language variants), or `ucrtbased`. The DLLs that ship in Windows (`msvcp_win`, `msvcrt`, `mfcore`, `mfc42`, ...) are not reported |
| ELF    | an RPATH or RUNPATH element that is `$ORIGIN`-based or relative (every element must be absolute); a `DT_NEEDED` that contains a `/` but does not start with one; a `PT_INTERP` that does not start with `/`                                                                                                                                                                                                                          |
| Mach-O | any `LC_RPATH`; a dylib load command that is `@executable_path`-, `@loader_path`- or `@rpath`-based or relative; an `LC_DYLD_ENVIRONMENT` that puts such a directory on a `DYLD_*_PATH` list (an empty element is not reported: dyld reads it as the root directory)                                                                                                                                                                 |

ELF files are read through their `PT_DYNAMIC` segment, not the section headers, so a binary without section headers is checked too. `verify` checks a developer's own build output for an accidental opt-in; a binary crafted to deceive it is out of scope. A file it cannot read as one of these formats is an error, not a pass. Universal Mach-O binaries are checked slice by slice.

## Platform notes

- **Windows targets other than MSVC** (`windows-gnu`, `windows-gnullvm`) **and Cygwin** (`target_os = "cygwin"`, whose executables are PE files loaded by the Windows loader): `bins()` fails the build. GNU ld has no `DEPENDENTLOADFLAG`, and the loader on those targets still searches the executable's folder, so the crate refuses rather than build a bin that looks hardened and is not. There is no switch to skip it.
- **MSVC targets without a prebuilt `core`** (tier 3 targets, `-Zbuild-std`): `bins()` fails the build. The initializer is compiled with the build's own `rustc` against the target's prebuilt `core`.
- **`+crt-static` passed only to the final crate**: `bins()` detects `+crt-static` through the target features cargo reports to the build script, which `RUSTFLAGS` and the target config set. `cargo rustc -- -C target-feature=+crt-static` reaches the final crate only and is not seen: the static-CRT link arguments are then emitted and make the Universal CRT dynamic.
- The library itself is not hardened: it ships no initializer and links no runtime tricks, so depending on it for `verify` changes nothing about the tests that use it.

## License

Apache-2.0.
