#[cfg(any(feature = "v0_16_0", feature = "v0_17_0", not(feature = "specific")))]
mod callback;
#[cfg(any(feature = "v0_16_0", feature = "v0_17_0", not(feature = "specific")))]
mod ring_buf;

#[cfg(any(feature = "v0_16_0", feature = "v0_17_0", not(feature = "specific")))]
pub use callback::*;
#[cfg(any(feature = "v0_16_0", feature = "v0_17_0", not(feature = "specific")))]
pub use ring_buf::*;
