extern crate uefi;
pub use uefi::table::runtime::VariableAttributes as EfiAttributes;
pub use uefi::Status as EfiStatus;

use std::ffi::c_void;
use std::slice;
use std::sync::Mutex;

use crate::varstore::*;

static PRIMARY_VARSTORE: Mutex<Varstore> = Mutex::new(Varstore::new());

/// # Safety
///
/// The C passed pointers will be zero checked and dereferenced.
/// It is in the callers interest to ensure they are memory backed if not null
pub unsafe extern "C" fn get_variable(
    c_variable_name: *const uefi::CString16,
    c_vendor_guid: *const uefi::Guid,
    c_attributes: *mut u32,
    c_data_size: *mut usize,
    c_data: *mut c_void,
) -> EfiStatus {
    if c_variable_name.is_null() {
        return uefi::Status::INVALID_PARAMETER;
    }

    if c_vendor_guid.is_null() {
        return uefi::Status::INVALID_PARAMETER;
    }

    if c_data_size.is_null() {
        return uefi::Status::INVALID_PARAMETER;
    }

    let mut data_size;
    let variable_name;
    let mut buf = None;
    let vendor_guid;
    let mut attributes = None;

    unsafe {
        data_size = *c_data_size;
        variable_name = &*c_variable_name;
        if !c_data.is_null() {
            buf = Some(slice::from_raw_parts_mut::<u8>(c_data.cast(), data_size));
        }
        if !c_attributes.is_null() {
            attributes = EfiAttributes::from_bits(*c_attributes);
        }
        vendor_guid = *c_vendor_guid;
    }

    // Convert UCS-2 to rust string
    let mut rust_name = String::new();
    if variable_name.as_str_in_buf(&mut rust_name).is_err() {
        return uefi::Status::INVALID_PARAMETER;
    }

    if let Ok(varstore) = PRIMARY_VARSTORE.lock() {
        let status = varstore.get_variable(
            &rust_name,
            &vendor_guid,
            attributes.as_mut(),
            buf,
            &mut data_size,
        );

        #[allow(clippy::unnecessary_unwrap)]
        if !c_attributes.is_null() && attributes.is_some() {
            unsafe { *c_attributes = attributes.unwrap().bits() }
        }

        status
    } else {
        uefi::Status::DEVICE_ERROR
    }
}
