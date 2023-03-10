bitflags::bitflags! {
    pub struct EfiAttribute: u32 {
        const NONE = 0;
        const RUNTIME_ACCESS = 1 << 0;
        const BOOTSERVICE_ACCESS = 1 << 1;
        const AUTHENTICATED_WRITE_ACCESS = 1 << 2;
        const TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 1 << 3;
        const ENHANCED_AUTHENTICATED_ACCESS = 1 << 4;
        const HARDWARE_ERROR = 1 << 5;
        const NON_VOLATILE = 1 << 6;
    }
}
