#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
    helpers::bpf_l4_csum_replace,
};
use core::mem;

#[repr(C)]
struct ethhdr { h_dest: [u8; 6], h_source: [u8; 6], h_proto: u16 }
#[repr(C)]
struct iphdr { _v: u8, _t: u8, _len: u16, _id: u16, _off: u16, _ttl: u8, proto: u8, _check: u16, saddr: u32, daddr: u32 }
#[repr(C)]
struct tcphdr { source: u16, dest: u16, _seq: u32, _ack: u32, _off: u16, _win: u16, check: u16, _urg: u16 }

#[classifier]
pub fn certes_ingress(ctx: TcContext) -> i32 {
    match try_certes_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

fn try_certes_ingress(ctx: TcContext) -> Result<i32, ()> {
    let eth_proto = u16::from_be(unsafe { *ptr_at::<u16>(&ctx, 12)? });
    if eth_proto != 0x0800 { return Ok(TC_ACT_OK); } // IPv4 only

    let ip_proto = unsafe { *ptr_at::<u8>(&ctx, 14 + 9)? };
    if ip_proto != 6 { return Ok(TC_ACT_OK); } // TCP only

    let tcp_dest_offset = 14 + 20 + 2; // Eth + IP + TCP Dest Port offset
    let mut dest_port = u16::from_be(unsafe { *ptr_at::<u16>(&ctx, tcp_dest_offset)? });

    if dest_port == 80 {
        let new_port: u16 = 8080;
        let old_port_be = u16::to_be(80);
        let new_port_be = u16::to_be(new_port);

        // 1. Rewrite the port in the packet
        unsafe {
            let port_ptr = (ctx.data() + tcp_dest_offset) as *mut u16;
            *port_ptr = new_port_be;
        }

        // 2. Fix the Checksum (Incremental)
        // Offset of 'check' in TCP header is 16 bytes from start of TCP header
        let csum_offset = 14 + 20 + 16;
        unsafe {
            bpf_l4_csum_replace(
                ctx.skb.skb,
                csum_offset as u32,
                old_port_be as u64,
                new_port_be as u64,
                2 | (1 << 4), // 2 bytes | BPF_F_PSEUDO_HDR
            );
        }
    }

    Ok(TC_ACT_OK)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end { return Err(()); }
    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { unsafe { core::hint::unreachable_unchecked() } }