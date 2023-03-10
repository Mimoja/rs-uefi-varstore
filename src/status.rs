#[derive(Debug)]
pub enum EfiStatus {
    Sucess = 0,
    DeviceError = 1,
    SecurityViolation = 2,
    InvalidParameter = 3,
    Unsupported = 4,
}
