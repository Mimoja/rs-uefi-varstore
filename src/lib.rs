extern crate binrw;
extern crate uefi;

pub use uefi::table::runtime::VariableAttributes as EfiAttributes;
pub use uefi::Status as EfiStatus;

// Contains rust definitions
pub mod varstore;
// Contains C Style interfaces
pub mod varstore_shim;
// Contains C ABI interfaces
pub mod varstore_sys;

//pub mod variable_authentication;

pub mod edk2;

pub use uefi::Guid;
