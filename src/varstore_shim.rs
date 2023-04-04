use std::convert::TryFrom;

use uefi::table::runtime::VariableAttributes as EfiAttributes;
use uefi::{CString16, Status as EfiStatus};

use crate::varstore::{EfiVariable, NextResponse, Varstore};

impl Varstore {
    pub fn set_variable(
        &mut self,
        name: String,
        vendor_guid: uefi::Guid,
        data: &[u8],
        attributes: EfiAttributes,
    ) -> Result<(), uefi::Status> {
        let var = EfiVariable::new(name, vendor_guid, data.to_vec(), attributes);
        self.request_set(&var)
    }

    pub fn get_variable(
        &self,
        name: &String,
        vendor_guid: &uefi::Guid,
        attributes: Option<&mut EfiAttributes>,
        data: Option<&mut [u8]>,
        data_size: &mut usize,
    ) -> EfiStatus {
        let var = self.request_get(name, *vendor_guid);
        match var {
            Ok(var) => {
                if let Some(attributes) = attributes {
                    *attributes = var.attr;
                    /*
                     * Unified Extensible Firmware Interface
                     *   (UEFI) Specification
                     *   Release 2.10
                     *   Page 209
                     * "The EFI_VARIABLE_APPEND_WRITE attribute will never be set in the returned Attributes bitmask parameter."
                     */
                    attributes.remove(EfiAttributes::APPEND_WRITE)
                }

                if *data_size < var.data.len() {
                    *data_size = var.data.len();
                    return EfiStatus::BUFFER_TOO_SMALL;
                }

                if data.is_none() {
                    return EfiStatus::INVALID_PARAMETER;
                }

                let data = data.unwrap();
                if data.len() != *data_size {
                    return EfiStatus::INVALID_PARAMETER;
                }

                *data_size = var.data.len();

                data.copy_from_slice(&var.data);

                EfiStatus::SUCCESS
            }
            Err(err) => err,
        }
    }

    pub fn get_next_variable(
        &self,
        name: &mut String,
        name_size: &mut usize,
        _vendor_guid: &mut uefi::Guid,
    ) -> EfiStatus {
        let next = self.request_get_next(name.to_string(), *_vendor_guid);
        match next {
            NextResponse::Found(next) => {
                let c16_name = CString16::try_from(next.name.as_str()).unwrap();
                let c16_len = c16_name.as_slice_with_nul().len();

                let new_size = c16_len * 2;
                if *name_size < new_size {
                    *name_size = new_size;
                    return EfiStatus::BUFFER_TOO_SMALL;
                }
                *name = next.name.clone();
                *name_size = new_size;
                EfiStatus::SUCCESS
            }
            NextResponse::EndReached => EfiStatus::NOT_FOUND,
            NextResponse::Invalid => EfiStatus::INVALID_PARAMETER,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::varstore::{EfiVariable, Varstore, TESTING_GUID};

    use crate::*;

    #[test]
    fn set_simple() {
        let mut varstore = Varstore::new();

        let status = varstore.set_variable(
            "TestExist".to_string(),
            TESTING_GUID,
            &vec![1, 2, 3, 4],
            EfiAttributes::BOOTSERVICE_ACCESS,
        );
        assert!(status.is_ok());

        assert!(varstore
            .request_get(&String::from("TestExist"), TESTING_GUID)
            .is_ok());
        assert_eq!(
            varstore
                .request_get(&String::from("TestExist"), TESTING_GUID)
                .unwrap()
                .data,
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn get_success() {
        let mut varstore = Varstore::new();
        let var = varstore.insert_new(
            "TestExist".to_string(),
            vec![1, 2, 3, 4],
            EfiAttributes::BOOTSERVICE_ACCESS,
        );

        let mut attributes = EfiAttributes::from_bits(0);
        let mut buf = [0u8; 4];
        let mut data_size = buf.len();

        let res = varstore.get_variable(
            &String::from("TestExist"),
            &TESTING_GUID,
            attributes.as_mut(),
            Some(buf.as_mut_slice()),
            &mut data_size,
        );
        assert!(res.is_success());
        assert_eq!(&buf, &[1, 2, 3, 4]);
        assert!(attributes
            .unwrap()
            .contains(EfiAttributes::BOOTSERVICE_ACCESS));
        assert!(attributes
            .unwrap()
            .complement()
            .contains(EfiAttributes::RUNTIME_ACCESS));
    }

    #[test]
    fn get_error() {
        let mut varstore = Varstore::new();
        let data = vec![1, 2, 3, 4];
        let data_len = data.len();
        let var = EfiVariable::new(
            "TestExist".to_string(),
            TESTING_GUID,
            data,
            EfiAttributes::BOOTSERVICE_ACCESS | EfiAttributes::RUNTIME_ACCESS,
        );

        varstore.insert(var.clone());

        let mut buf = [0u8; 4];
        let mut data_size = 0;

        // No Buffer, but enough size
        data_size = 10;
        let res = varstore.get_variable(
            &String::from("TestExist"),
            &TESTING_GUID,
            None,
            None,
            &mut data_size,
        );
        assert_eq!(res, EfiStatus::INVALID_PARAMETER);

        // No Buffer, not enough size
        data_size = 0;
        let res = varstore.get_variable(
            &String::from("TestExist"),
            &TESTING_GUID,
            None,
            None,
            &mut data_size,
        );
        assert_eq!(res, EfiStatus::BUFFER_TOO_SMALL);
        assert_eq!(data_size, data_len);

        // Buffer != size
        data_size = buf.len() + 1;
        let res = varstore.get_variable(
            &String::from("TestExist"),
            &TESTING_GUID,
            None,
            Some(buf.as_mut_slice()),
            &mut data_size,
        );
        assert_eq!(res, EfiStatus::INVALID_PARAMETER);
    }
}
