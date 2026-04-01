#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::classifier,
    programs::TcContext,
    helpers::{bpf_l4_csum_replace, bpf_printk},
};
use core::mem;


const PORT_80: u16 = 80u16.to_be();
const PORT_8080: u16 = 8080u16.to_be();

#[allow(dead_code)]
#[repr(C)]
struct ethhdr { h_dest: [u8; 6], h_source: [u8; 6], h_proto: u16 }
#[allow(dead_code)]
#[repr(C)]
struct iphdr { _v: u8, _t: u8, _len: u16, _id: u16, _off: u16, _ttl: u8, proto: u8, _check: u16, saddr: u32, daddr: u32 }
#[allow(dead_code)]
#[repr(C)]
struct tcphdr { source: u16, dest: u16, _seq: u32, _ack: u32, _off: u16, _win: u16, check: u16, _urg: u16 }

#[classifier]
pub fn certes_ingress(ctx: TcContext) -> i32 {
    let _ = try_certes_ingress(ctx);
    TC_ACT_OK
}

fn try_certes_ingress(ctx: TcContext) -> Result<(), ()> {
    if !is_ipv4_tcp(&ctx)? { return Ok(()); }
    let tcp_dest_off = 14 + 20 + 2; 
    let port_ptr = unsafe { ptr_at::<u16>(&ctx, tcp_dest_off)? } as *mut u16;
    let dest_port = unsafe { *port_ptr };

    if dest_port == PORT_80 {
        // METADATA LOGGING: bpf_printk uses the kernel trace buffer.
        // No maps required = no relocation errors.
        unsafe {
            bpf_printk!(b"REDIRECT: 80 -> 8080");
            *port_ptr = PORT_8080;
            bpf_l4_csum_replace(ctx.skb.skb, 14 + 20 + 16, dest_port as u64, PORT_8080 as u64, 2 | (1 << 4));
        }
    }
    Ok(())
}

#[classifier]
pub fn certes_egress(ctx: TcContext) -> i32 {
    let _ = try_certes_egress(ctx);
    TC_ACT_OK
}

fn try_certes_egress(ctx: TcContext) -> Result<(), ()> {
    if !is_ipv4_tcp(&ctx)? { return Ok(()); }
    let tcp_src_off = 14 + 20; 
    let port_ptr = unsafe { ptr_at::<u16>(&ctx, tcp_src_off)? } as *mut u16;
    let src_port = unsafe { *port_ptr };

    if src_port == PORT_8080 {
        unsafe {
            bpf_printk!(b"REVERT: 8080 -> 80");
            *port_ptr = PORT_80;
            bpf_l4_csum_replace(ctx.skb.skb, 14 + 20 + 16, src_port as u64, PORT_80 as u64, 2 | (1 << 4));
        }
    }
    Ok(())
}

#[inline(always)]
fn is_ipv4_tcp(ctx: &TcContext) -> Result<bool, ()> {
    let eth_proto = u16::from_be(unsafe { *ptr_at::<u16>(ctx, 12)? });
    if eth_proto != 0x0800 { return Ok(false); }
    let ip_proto = unsafe { *ptr_at::<u8>(ctx, 14 + 9)? };
    Ok(ip_proto == 6)
}

// #[inline(always)]
// unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
//     let start = ctx.data();
//     let end = ctx.data_end();
//     if start + offset + mem::size_of::<T>() > end { return Err(()); }
//     Ok((start + offset) as *const T)
// }

/// Core memory safety logic. Tested on host, executed in kernel.
#[inline(always)]
unsafe fn check_bounds<T>(start: usize, end: usize, offset: usize) -> Result<*const T, ()> {
    let len = mem::size_of::<T>();
    // The exact check the eBPF verifier requires
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Kernel-specific wrapper
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    unsafe {
    check_bounds::<T>(ctx.data(), ctx.data_end(), offset)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { unsafe { core::hint::unreachable_unchecked() } }


#[cfg(test)]
mod tests {

    extern crate std;
    use super::*;

    #[test]
    fn test_ptr_at_real_memory() {
        // Use a stack-allocated array instead of vec!
        let packet = [0u8; 100]; 
        let start = packet.as_ptr() as usize;
        let end = start + packet.len();

        unsafe {
            // 1. Test a valid read (Reading a u16 at offset 10)
            let res = check_bounds::<u16>(start, end, 10);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), (start + 10) as *const u16);

            // 2. Test an Out-of-Bounds read (Reading a u64 at the very end)
            // Offset 95 + 8 bytes = 103 (OOB)
            let res_oob = check_bounds::<u64>(start, end, 95);
            assert!(res_oob.is_err(), "Should have failed OOB check");

            // 3. Test exact boundary condition
            // Offset 92 + 8 bytes = 100 (Perfect fit)
            let res_edge = check_bounds::<u64>(start, end, 92);
            assert!(res_edge.is_ok(), "Should allow reading up to the last byte");
        }
    }
}