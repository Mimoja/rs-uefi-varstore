use binrw::{io::Cursor, BinRead, NullString, NullWideString};
use bitflags::bitflags;
use uefi::table::runtime::{VariableAttributes as EfiAttributes, VariableStorageInfo};
use uefi::Guid;

use crate::varstore::EfiVariable;

bitflags! {
    #[derive(Debug, Clone)]
    /// Flags describing the attributes of a FVB2.
    pub struct EDK2FirmwareVolume2Attributes: u32 {
        const READ_DISABLED_CAP  = 0x00000001;
        const READ_ENABLED_CAP   = 0x00000002;
        const READ_STATUS        = 0x00000004;
        const WRITE_DISABLED_CAP = 0x00000008;
        const WRITE_ENABLED_CAP  = 0x00000010;
        const WRITE_STATUS       = 0x00000020;
        const LOCK_CAP           = 0x00000040;
        const LOCK_STATUS        = 0x00000080;
        const STICKY_WRITE       = 0x00000200;
        const MEMORY_MAPPED      = 0x00000400;
        const ERASE_POLARITY     = 0x00000800;
        const READ_LOCK_CAP      = 0x00001000;
        const READ_LOCK_STATUS   = 0x00002000;
        const WRITE_LOCK_CAP     = 0x00004000;
        const WRITE_LOCK_STATUS  = 0x00008000;
        const ALIGNMENT          = 0x001F0000;
        const ALIGNMENT_1        = 0x00000000;
        const ALIGNMENT_2        = 0x00010000;
        const ALIGNMENT_4        = 0x00020000;
        const ALIGNMENT_8        = 0x00030000;
        const ALIGNMENT_16       = 0x00040000;
        const ALIGNMENT_32       = 0x00050000;
        const ALIGNMENT_64       = 0x00060000;
        const ALIGNMENT_128      = 0x00070000;
        const ALIGNMENT_256      = 0x00080000;
        const ALIGNMENT_512      = 0x00090000;
        const ALIGNMENT_1K       = 0x000A0000;
        const ALIGNMENT_2K       = 0x000B0000;
        const ALIGNMENT_4K       = 0x000C0000;
        const ALIGNMENT_8K       = 0x000D0000;
        const ALIGNMENT_16K      = 0x000E0000;
        const ALIGNMENT_32K      = 0x000F0000;
        const ALIGNMENT_64K      = 0x00100000;
        const ALIGNMENT_128K     = 0x00110000;
        const ALIGNMENT_256K     = 0x00120000;
        const ALIGNMENT_512K     = 0x00130000;
        const ALIGNMENT_1M       = 0x00140000;
        const ALIGNMENT_2M       = 0x00150000;
        const ALIGNMENT_4M       = 0x00160000;
        const ALIGNMENT_8M       = 0x00170000;
        const ALIGNMENT_16M      = 0x00180000;
        const ALIGNMENT_32M      = 0x00190000;
        const ALIGNMENT_64M      = 0x001A0000;
        const ALIGNMENT_128M     = 0x001B0000;
        const ALIGNMENT_256M     = 0x001C0000;
        const ALIGNMENT_512M     = 0x001D0000;
        const ALIGNMENT_1G       = 0x001E0000;
        const ALIGNMENT_2G       = 0x001F0000;
        const WEAK_ALIGNMENT     = 0x80000000;
    }
}

bitflags! {
    #[derive(Debug, Clone)]
    pub struct EDK2VaribleState: u8 {
        const IN_DELETED_TRANSITION = 0xfe; // Variable is in obsolete transition.
        const DELETED               = 0xfd; // Variable is obsolete.
        const HEADER_VALID_ONLY     = 0x7f; // Variable header has been valid.
        const VAR_ADDED             = 0x3f; // Variable has been completely added.
        // VAR_ADDED & IN_DELETED_TRANSITION & DELETED
        const ADDED_AND_DELETED     = 0x3c; // Variable has been in all states above
     }
}

impl EDK2VaribleState {
    fn is_valid(&self) -> bool {
        return self.bits() == EDK2VaribleState::VAR_ADDED.bits();
    }
}

#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct EDK2VariableHeader {
    #[br(assert(ZeroVector.iter().all(|&x| x == 0)))]
    ZeroVector: [u8; 16],

    // fff12b8d-7696-4c8b-a985-2747075b4f50
    #[br(map = |x: [u8; 16]| Guid::from_bytes(x))]
    #[br(assert(FSGuid.to_string() == "fff12b8d-7696-4c8b-a985-2747075b4f50"))]
    FSGuid: Guid,

    Length: u64,

    #[br(assert(Signatur.to_vec() == b"_FVH".to_vec()))]
    Signatur: [u8; 4],

    #[br(map = |x: u32| EDK2FirmwareVolume2Attributes::from_bits(x).unwrap())]
    Attributes: EDK2FirmwareVolume2Attributes,

    #[br(assert(HeaderLength == 0x48))]
    HeaderLength: u16,

    HeaderCheckSum: u16,

    #[br(pad_before = 3, assert(Revision == 0x02))]
    Revision: u8,

    #[br(pad_before = 0x10)]
    #[br(map = |x: [u8; 16]| Guid::from_bytes(x))]
    #[br(assert(VSGuid.to_string() == "aaf32c78-947b-439a-a180-2e144ec37792"))]
    VSGuid: Guid,

    VariableSize: u32,
    Status: [u8; 8],
}

#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct EDK2Variable {
    #[br(assert(Signature == 0x55aa),  align_before = 4)]
    Signature: u16,

    #[br(map = |x: u8| EDK2VaribleState::from_bits(x).unwrap())]
    Status: EDK2VaribleState,

    #[br(pad_before = 1, map = |x: u32| EfiAttributes::from_bits(x).unwrap())]
    Attributes: EfiAttributes,
    Monotoniccount: u64,
    Timestamp: [u8; 16],
    //timestamp: uefi::table::runtime::Time,
    PubkeyIdx: u32,
    Namelen: u32,
    Datalen: u32,
    #[br(map = |x: [u8; 16]| Guid::from_bytes(x))]
    Guid: Guid,
    #[br(count= Namelen / 2, map = |x: Vec<u16>| uefi::CString16::try_from(x).unwrap())]
    Name: uefi::CString16,
    #[br(count = Datalen)]
    Data: Vec<u8>,
}

#[derive(BinRead, Debug, Clone)]
#[br(little)]
pub struct EDK2VariableStore {
    Header: EDK2VariableHeader,
    //FIXME Use proper alignment calculation
    #[br(count = Header.VariableSize / 725)]
    //#[br(count = 40)]
    Variables: Vec<EDK2Variable>,
}

impl EDK2VariableStore {
    fn from_bytes(edk2bytes: Vec<u8>) -> Result<(Vec<EfiVariable>, EDK2VariableStore), ()> {
        let mut reader = Cursor::new(edk2bytes);
        //FIXME return error
        let store: EDK2VariableStore = binrw::BinReaderExt::read_ne(&mut reader).unwrap();

        let mut vars: Vec<EfiVariable>= vec![];

        for var in store.Variables.iter() {
            if var.Status.bits() != EDK2VaribleState::VAR_ADDED.bits() {
                continue;
            }

            vars.push(EfiVariable { name: var.Name.to_string(), guid: var.Guid, data: var.Data.clone(), attr: var.Attributes });
        }
        Ok((vars, store))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parseExampleFile() {
        let variable_store = include_bytes!("../testdata/OVMF_VARS-1920x1080.fd");
        let parsed = EDK2VariableStore::from_bytes(variable_store.to_vec());
        assert!(parsed.is_ok());

        let (vars, store) = parsed.unwrap();

        assert_eq!(vars.len(), 44);
        assert_eq!(store.Variables.len(), 78);

        assert!(store.Header.Attributes.contains(
            EDK2FirmwareVolume2Attributes::READ_DISABLED_CAP
                | EDK2FirmwareVolume2Attributes::READ_ENABLED_CAP
                | EDK2FirmwareVolume2Attributes::READ_STATUS
                | EDK2FirmwareVolume2Attributes::WRITE_DISABLED_CAP
                | EDK2FirmwareVolume2Attributes::WRITE_ENABLED_CAP
                | EDK2FirmwareVolume2Attributes::WRITE_STATUS
                | EDK2FirmwareVolume2Attributes::LOCK_CAP
                | EDK2FirmwareVolume2Attributes::LOCK_STATUS
                | EDK2FirmwareVolume2Attributes::STICKY_WRITE
                | EDK2FirmwareVolume2Attributes::MEMORY_MAPPED
                | EDK2FirmwareVolume2Attributes::ERASE_POLARITY
                | EDK2FirmwareVolume2Attributes::READ_LOCK_CAP
                | EDK2FirmwareVolume2Attributes::READ_LOCK_STATUS
                | EDK2FirmwareVolume2Attributes::WRITE_LOCK_CAP
                | EDK2FirmwareVolume2Attributes::WRITE_LOCK_STATUS
                | EDK2FirmwareVolume2Attributes::ALIGNMENT_16
        ));

        for var in store.Variables.iter() {

            eprintln!(
                "{:?}(valid={:?})",
                var.Name.to_string(),
                var.Status.is_valid()
            );
        }
    }
}
