#[cfg(not(feature = "usdt"))]
mod v0_4_0;

#[cfg(not(feature = "usdt"))]
pub use self::v0_4_0::{usdt_generate_args, USDTContext};

#[cfg(feature = "usdt")]
mod v0_10_0;

#[cfg(feature = "usdt")]
pub use self::v0_10_0::{usdt_generate_args, USDTContext};
