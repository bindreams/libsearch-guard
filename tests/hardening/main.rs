//! End-to-end: build the probe fixture the way a consumer would, hardened and not, then verify it and, on
//! Windows, watch what its DLL loads do.

mod dll_search;
mod fixtures;
mod verifier;
