#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub port: u16,
    pub action: u16, // 1 for Redirect, 2 for Return
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}