//! The consumer side of libsearch-guard, as a consumer writes it. The tests set the variable to build the
//! hardened probe and leave it unset for the plain one.

fn main() {
    if std::env::var_os("LIBSEARCH_GUARD_HARDEN_PROBE").is_some() {
        libsearch_guard::bins();
    }
}
