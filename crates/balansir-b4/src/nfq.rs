//! NFQUEUE netlink protocol constants (from linux uapi
//! `netfilter/nfnetlink_queue.h` and `nfnetlink.h`).
//!
//! These are stable ABI constants; kept here so the Rust engine needs no C
//! headers at build time.

#![allow(dead_code)]

/// Netlink protocol family for netfilter (NETLINK_NETFILTER = 12).
pub const NETLINK_NETFILTER: i32 = 12;
/// Netfilter subsystem: NFNL_SUBSYS_QUEUE = 3.
pub const NFNL_SUBSYS_QUEUE: u8 = 3;

/// `(subsys << 8) | msg_type` — NFNL_MSG_TYPE.
pub fn nfgenmsg_type(subsys: u8, msg_type: u8) -> u16 {
    ((subsys as u16) << 8) | (msg_type as u16)
}

// --- nfnetlink message types (nfnetlink.h) ---
pub const NFNL_MSG_BATCH_BEGIN: u8 = 0x10;
pub const NFNL_MSG_BATCH_END: u8 = 0x11;

// --- nfnetlink_queue message types (nfnetlink_queue.h) ---
pub const NFQNL_MSG_PACKET: u8 = 0; // kernel -> userspace
pub const NFQNL_MSG_VERDICT: u8 = 1; // userspace -> kernel
pub const NFQNL_MSG_CONFIG: u8 = 2; // connect/configure a queue
pub const NFQNL_MSG_VERDICT_BATCH: u8 = 3;

// --- nfgenmsg (nfnetlink.h) ---
pub const NFNETLINK_V0: u8 = 0;
pub const NFPROTO_UNSPEC: u8 = 0;
pub const NFPROTO_INET: u8 = 1;

// --- nfqnl attributes (nfnetlink_queue.h) ---
pub const NFQA_UNSPEC: u16 = 0;
pub const NFQA_PACKET_HDR: u16 = 1;
pub const NFQA_VERDICT_HDR: u16 = 2;
pub const NFQA_MARK: u16 = 3;
pub const NFQA_TIMESTAMP: u16 = 4;
pub const NFQA_IFINDEX_INDEV: u16 = 5;
pub const NFQA_IFINDEX_OUTDEV: u16 = 6;
pub const NFQA_IFINDEX_PHYSINDEV: u16 = 7;
pub const NFQA_IFINDEX_PHYSOUTDEV: u16 = 8;
pub const NFQA_HWADDR: u16 = 9;
pub const NFQA_PAYLOAD: u16 = 10;
pub const NFQA_CT: u16 = 11;
pub const NFQA_CT_INFO: u16 = 12;
pub const NFQA_CAP_LEN: u16 = 13;
pub const NFQA_SKB_INFO: u16 = 14;
pub const NFQA_EXP: u16 = 15;
pub const NFQA_UID: u16 = 16;
pub const NFQA_GID: u16 = 17;
pub const NFQA_SECCTX: u16 = 18;
pub const NFQA_VLAN: u16 = 19;

// --- NFQNL_CFG_CMD (nfnetlink_queue.h) ---
pub const NFQNL_CFG_CMD_NONE: u8 = 0;
pub const NFQNL_CFG_CMD_BIND: u8 = 1;
pub const NFQNL_CFG_CMD_UNBIND: u8 = 2;
pub const NFQNL_CFG_CMD_PF_BIND: u8 = 3;
pub const NFQNL_CFG_CMD_PF_UNBIND: u8 = 4;

// --- NFQNL_CFG_CMD attribute (nested under NFQA_CFG) ---
pub const NFQNL_CFG_CMD_CMD: u16 = 1;
pub const NFQNL_CFG_CMD_PF: u16 = 2;

// --- NFQNL_CFG_* attributes (top-level config attrs) ---
pub const NFQA_CFG_CMD: u16 = 1;
pub const NFQA_CFG_PARAMS: u16 = 2;
pub const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
pub const NFQA_CFG_MASK: u16 = 4;
pub const NFQA_CFG_FLAGS: u16 = 5;

// --- NFQNL_CFG_F_* flags ---
pub const NFQNL_CFG_F_SEQ: u32 = 1 << 0;
pub const NFQNL_CFG_F_GSO: u32 = 1 << 1;
pub const NFQNL_CFG_F_CONNTRACK: u32 = 1 << 2;
pub const NFQNL_CFG_F_GSO_META: u32 = 1 << 3;

// --- copy modes ---
pub const NFQNL_COPY_NONE: u8 = 0;
pub const NFQNL_COPY_META: u8 = 1;
pub const NFQNL_COPY_PACKET: u8 = 2;

// --- verdict (nfnetlink_queue.h) ---
/// nfqnl_msg_verdict_hdr.v:
pub const NF_ACCEPT: u8 = 1;
pub const NF_DROP: u8 = 0;
pub const NF_REPEAT: u8 = 2;
pub const NF_STOLEN: u8 = 4;

/// nfqnl_msg_packet_hdr fields (NFQA_PACKET_HDR payload, 8 bytes):
///   packet_id: u32 (network byte order)
///   hw_protocol: u16 (network byte order)
///   hook: u8
pub const NFQA_PACKET_HDR_LEN: usize = 8;

/// nfqnl_msg_verdict_hdr fields (NFQA_VERDICT_HDR payload, 4 bytes):
///   verdict: u32 (network byte order)
pub const NFQA_VERDICT_HDR_LEN: usize = 4;

/// Maximum queue number (kernel: ~64k queues).
pub const NFQNL_MAX_QUEUE: u32 = 65535;
