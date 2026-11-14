#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Reusable `#![no_std]` + `alloc` authorization core for `mu-console` and platform services.

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;
