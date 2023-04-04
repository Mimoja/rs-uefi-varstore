#[macro_use]
extern crate bitflags;


#[derive(Debug, Clone, BinRead)]
#[br(assert(Pad1 == 0 && Pad2 == 0))]
struct EFI_TIME {
    Year: u16,
    Month: u8,
    Day: u8,
    Hour: u8,
    Minute: u8,
    Second: u8,
    Pad1: u8,
    Nanosecond: u32,
    TimeZone: i16,
    Daylight: u8,
    Pad2: u8,
}

#[derive(Debug, Clone, BinRead)]
struct WIN_CERTIFICATE {
    dwLength: u32,
    wRevision: u16,
    wCertificateType: u16,
}

#[derive(Debug, Clone, BinRead)]
pub struct WIN_CERTIFICATE_UEFI_GUID {
    Hdr: WIN_CERTIFICATE,
    CertType: EFI_GUID,
}

#[derive(Debug, Clone, BinRead)]
#[br(assert(AuthInfo.Hdr.wCertificateType == WIN_CERT_TYPE_EFI_GUID))]
struct EFI_VARIABLE_AUTHENTICATION_2 {
    TimeStamp: EFI_TIME,
    AuthInfo: WIN_CERTIFICATE_UEFI_GUID,

    #[br(offset = 40, count = AuthInfo.Hdr.dwLength as usize
        - mem::size_of::<WIN_CERTIFICATE_UEFI_GUID>())]
    SignData: Vec<u8>,

    #[br(count = 0)]
    PayloadData: Vec<u8>,
}

#[derive(Debug, Clone, BinRead)]
#[br(import { SignatureSize: usize })]
struct EFI_SIGNATURE_DATA {
    SignatureOwner: EFI_GUID,
    #[br(count = SignatureSize - mem::size_of::<EFI_GUID>())]
    SignatureData: Vec<u8>,
}

#[derive(Debug, Clone, BinRead)]
struct EFI_SIGNATURE_LIST {
    SignatureType: EFI_GUID,
    SignatureListSize: u32,
    SignatureHeaderSize: u32,
    SignatureSize: u32,

    #[br(count = SignatureHeaderSize)]
    Header: Vec<u8>,

    #[br(
        count = (
                    SignatureListSize as usize
                    - SignatureHeaderSize as usize
                    - mem::size_of::<EFI_GUID>()
                    - (mem::size_of::<u32>() * 3)
                ) / SignatureSize as usize,
        args {inner : args!{SignatureSize : SignatureSize as usize}}
        )
    ]
    SignatureData: Vec<EFI_SIGNATURE_DATA>,
}