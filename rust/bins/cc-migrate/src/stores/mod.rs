//! Every store the Rust build reads, one file per workstream so they never edit the same lines
//! (appendix B §2, D §2b-2c).

use crate::store::Store;

mod w0;
mod w3;
mod w4;
mod w5;
mod w6;
mod w7;
mod w8;

pub fn all() -> impl Iterator<Item = &'static Store> {
    [
        w0::STORES,
        w3::STORES,
        w4::STORES,
        w5::STORES,
        w6::STORES,
        w7::STORES,
        w8::STORES,
    ]
    .into_iter()
    .flatten()
}
