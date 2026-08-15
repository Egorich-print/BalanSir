//! NFQUEUE engine: bind to a kernel NFQUEUE, receive packets, return verdicts.
//!
//! Pure-Rust implementation over `netlink-sys` (`NETLINK_NETFILTER` socket).
//! No libnetfilter-queue C dependency. Protocol per linux uapi
//! `nfnetlink_queue.h`:
//!
//! 1. Open `NETLINK_NETFILTER` socket, bind to the netfilter group.
//! 2. Send `NFQNL_MSG_CONFIG` with `PF_BIND` then `BIND` + copy-mode params.
//! 3. Receive `NFQNL_MSG_PACKET` messages (each carries a packet id + payload).
//! 4. Send `NFQNL_MSG_VERDICT` back with a verdict (and optionally an
//!    NFQA_VERDICT_HDR with a modified packet).
//!
//! This is the interception primitive the DPI-bypass strategies build on.

use crate::nfq::*;
use std::io;
use std::os::unix::io::AsRawFd;

/// A packet received from the kernel queue.
#[derive(Debug, Clone)]
pub struct QueuedPacket {
    /// Kernel-assigned packet id (echoed in the verdict).
    pub packet_id: u32,
    /// Ingress interface index (NFQA_IFINDEX_INDEV), if present.
    pub indev: Option<u32>,
    /// Egress interface index (NFQA_IFINDEX_OUTDEV), if present.
    pub outdev: Option<u32>,
    /// Raw IP packet payload (NFQA_PAYLOAD), present in COPY_PACKET mode.
    pub payload: Option<Vec<u8>>,
    /// Captured length (NFQA_CAP_LEN) when the payload was truncated.
    pub cap_len: Option<u32>,
}

/// Parsed netfilter netlink message (subset needed by NFQUEUE).
#[derive(Debug)]
enum NfMessage {
    Packet(QueuedPacket),
    Other,
}

/// NFQUEUE socket handle bound to one queue number.
pub struct NfQueue {
    sock: netlink_sys::Socket,
    queue_num: u16,
    /// Max payload bytes the kernel copies per packet (COPY_PACKET).
    copy_range: u32,
}

impl NfQueue {
    /// Open and bind to a kernel NFQUEUE.
    pub fn new(queue_num: u16, copy_range: u32) -> io::Result<Self> {
        tracing::info!(queue = queue_num, "NFQUEUE: opening socket");
        let mut sock = netlink_sys::Socket::new(NETLINK_NETFILTER as isize)?;
        sock.bind_auto()?;
        tracing::info!(queue = queue_num, "NFQUEUE: socket bound");
        let queue = Self {
            sock,
            queue_num,
            copy_range,
        };
        queue.configure()?;
        tracing::info!(queue = queue_num, "NFQUEUE: configure complete");
        Ok(queue)
    }

    fn configure(&self) -> io::Result<()> {
        // libnetfilter_queue: PF_UNBIND/PF_BIND use res_id=0, queue BIND and
        // params use the queue number.
        let pf_unbind = self.config_msg(NFQNL_CFG_CMD_PF_UNBIND, Some(AF_INET), 0);
        tracing::info!(msg = %hex(&pf_unbind), "NFQUEUE PF_UNBIND");
        self.send_config(&pf_unbind)?;
        let pf_bind = self.config_msg(NFQNL_CFG_CMD_PF_BIND, Some(AF_INET), 0);
        tracing::info!(msg = %hex(&pf_bind), "NFQUEUE PF_BIND");
        self.send_config(&pf_bind)?;
        let bind = self.config_msg(NFQNL_CFG_CMD_BIND, None, self.queue_num);
        tracing::info!(msg = %hex(&bind), "NFQUEUE BIND");
        self.send_config(&bind)?;
        let params = self.config_params();
        tracing::info!(msg = %hex(&params), "NFQUEUE PARAMS");
        self.send_config(&params)?;

        // Diagnostic: confirm the kernel registered the queue.
        if let Ok(proc) = std::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue") {
            if proc.trim().is_empty() {
                tracing::warn!(
                    queue = self.queue_num,
                    "NFQUEUE bind: /proc/net/netfilter/nfnetlink_queue is empty after configure"
                );
            } else {
                tracing::info!(
                    queue = self.queue_num,
                    "NFQUEUE registered: {}",
                    proc.lines().next().unwrap_or("")
                );
            }
        }
        Ok(())
    }

    /// Send a config message with NLM_F_ACK and read the kernel's reply so a
    /// rejected command surfaces as an error instead of a silent no-op.
    fn send_config(&self, buf: &[u8]) -> io::Result<()> {
        // Patch the flags byte (offset 6..8) to add NLM_F_ACK (0x4).
        let mut with_ack = buf.to_vec();
        if with_ack.len() >= 8 {
            let flags = u16::from_ne_bytes([with_ack[6], with_ack[7]]);
            with_ack[6..8].copy_from_slice(&(flags | netlink_packet_core::NLM_F_ACK).to_ne_bytes());
        }
        self.sock.send(&with_ack, 0)?;
        // Read the reply (ACK or NLMSG_ERROR). Short timeout to avoid hang.
        let mut reply = vec![0u8; 512];
        let n = self.sock.recv(&mut reply, 0)?;
        if n >= 4 {
            // Netlink message type: NLMSG_ERROR = 2.
            let mtype = u16::from_ne_bytes([reply[4], reply[5]]);
            if mtype == 2 && n >= 16 {
                let err = i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]);
                if err != 0 {
                    return Err(io::Error::from_raw_os_error(-err));
                }
            }
        }
        Ok(())
    }

    /// Build an `NFQNL_MSG_CONFIG` message.
    fn config_msg(&self, cmd: u8, pf: Option<u8>, res_id: u16) -> Vec<u8> {
        let mut attrs: Vec<u8> = Vec::new();
        // NFQA_CFG_CMD payload = struct nfqnl_msg_config_cmd (4 bytes):
        //   command: u8
        //   _pad: u8
        //   pf: __be16  (AF_* family, only for PF_BIND/PF_UNBIND)
        let mut cmd_struct = Vec::with_capacity(4);
        cmd_struct.push(cmd);
        cmd_struct.push(0);
        // pf is __be16 (AF_*), not a single byte.
        cmd_struct.extend_from_slice(&(pf.unwrap_or(0) as u16).to_be_bytes());
        push_nla(&mut attrs, NFQA_CFG_CMD, &cmd_struct);

        self.netlink_msg(NFQNL_MSG_CONFIG, attrs, res_id)
    }

    fn config_params(&self) -> Vec<u8> {
        // NFQA_CFG_PARAMS payload (struct nfqnl_msg_config_params, 8 bytes):
        //   copy_range: u32 (network order)
        //   copy_mode: u8
        //   _pad[3]: u8
        let mut params = Vec::with_capacity(8);
        params.extend_from_slice(&self.copy_range.to_be_bytes());
        params.push(NFQNL_COPY_PACKET);
        params.extend_from_slice(&[0u8; 3]);

        let mut attrs = Vec::new();
        push_nla(&mut attrs, NFQA_CFG_PARAMS, &params);
        // flags: NFQNL_CFG_F_SEQ | NFQNL_CFG_F_GSO (helps id/payload handling)
        push_nla(
            &mut attrs,
            NFQA_CFG_FLAGS,
            &(NFQNL_CFG_F_SEQ | NFQNL_CFG_F_GSO).to_be_bytes(),
        );
        // generous queue maxlen to avoid drops under load
        push_nla(&mut attrs, NFQA_CFG_QUEUE_MAXLEN, &4096u32.to_be_bytes());

        self.netlink_msg(NFQNL_MSG_CONFIG, attrs, self.queue_num)
    }

    /// Build a netlink message: `nfgenmsg` header + attributes.
    fn netlink_msg(&self, msg_type: u8, attrs: Vec<u8>, queue_num: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        // nfgenmsg: family(1) + version(1) + res_id(2). For NFQUEUE config
        // messages the family is NFPROTO_UNSPEC (0); the AF_* is carried in
        // the NFQNL_CFG_CMD_PF attribute (libnetfilter_queue does the same).
        payload.push(NFPROTO_UNSPEC);
        payload.push(NFNETLINK_V0);
        payload.extend_from_slice(&queue_num.to_be_bytes());
        payload.extend_from_slice(&attrs);

        let inner_type = nfgenmsg_type(NFNL_SUBSYS_QUEUE, msg_type);
        // Netlink header fields are in *host* byte order (native endianness);
        // only netfilter payload attributes use network order.
        let total_len = (16 + payload.len()) as u32;
        let mut msg = Vec::with_capacity(total_len as usize);
        msg.extend_from_slice(&total_len.to_ne_bytes());
        msg.extend_from_slice(&inner_type.to_ne_bytes());
        msg.extend_from_slice(&(netlink_packet_core::NLM_F_REQUEST as u16).to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes()); // sequence
        msg.extend_from_slice(&0u32.to_ne_bytes()); // port
        msg.extend_from_slice(&payload);
        msg
    }

    fn send(&self, buf: &[u8]) -> io::Result<()> {
        self.sock.send(buf, 0).map(|_| ())
    }

    /// Blocking receive of one message; returns the parsed packet.
    pub fn recv_packet(&self) -> io::Result<Option<QueuedPacket>> {
        let mut buf = vec![0u8; 65536];
        let n = self.sock.recv(&mut buf, 0)?;
        let msg = parse_netfilter_message(&buf[..n])?;
        match msg {
            NfMessage::Packet(p) => Ok(Some(p)),
            NfMessage::Other => Ok(None),
        }
    }

    /// Send a verdict for a packet, optionally replacing the payload.
    ///
    /// `verdict` is one of NF_ACCEPT / NF_DROP / NF_REPEAT / NF_STOLEN.
    /// When `payload` is `Some`, the packet is replaced with it (DPI mutation).
    pub fn verdict(&self, packet_id: u32, verdict: u8, payload: Option<&[u8]>) -> io::Result<()> {
        let mut attrs: Vec<u8> = Vec::new();
        // NFQA_VERDICT_HDR: u32 verdict (network order).
        let verdict_bytes = (verdict as u32).to_be_bytes();
        push_nla(&mut attrs, NFQA_VERDICT_HDR, &verdict_bytes);
        if let Some(p) = payload {
            push_nla(&mut attrs, NFQA_PAYLOAD, p);
        }
        let msg = self.netlink_msg(NFQNL_MSG_VERDICT, attrs, self.queue_num);
        self.sock.send(&msg, 0).map(|_| ())
    }

    /// Underlying socket fd (for integration with async runtimes if needed).
    pub fn as_raw_fd(&self) -> i32 {
        self.sock.as_raw_fd()
    }
}

/// Append a netlink attribute (nla) with `type` and `data` payload.
fn push_nla(buf: &mut Vec<u8>, nla_type: u16, data: &[u8]) {
    let len = (data.len() + 4) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&nla_type.to_ne_bytes());
    buf.extend_from_slice(data);
    // align to 4
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

/// Parse a netfilter netlink message into an NFQUEUE packet (or Other).
fn parse_netfilter_message(buf: &[u8]) -> io::Result<NfMessage> {
    if buf.len() < 16 {
        return Ok(NfMessage::Other);
    }
    let header = &buf[..16];
    let length = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let msg_type = u16::from_ne_bytes([header[4], header[5]]);
    if length < 16 || length > buf.len() {
        return Ok(NfMessage::Other);
    }
    let body = &buf[16..length];
    // nfgenmsg: family(1) version(1) res_id(2)
    if body.len() < 4 {
        return Ok(NfMessage::Other);
    }
    let _family = body[0];
    let _version = body[1];
    let res_id = u16::from_be_bytes([body[2], body[3]]);
    let _ = res_id;

    // NFQNL_MSG_PACKET = type & 0xFF (msg_type is (subsys<<8)|msg)
    let msg_kind = (msg_type & 0xff) as u8;
    if msg_kind != NFQNL_MSG_PACKET {
        return Ok(NfMessage::Other);
    }

    let attrs = &body[4..];
    let mut packet = QueuedPacket {
        packet_id: 0,
        indev: None,
        outdev: None,
        payload: None,
        cap_len: None,
    };

    let mut pos = 0;
    while pos + 4 <= attrs.len() {
        let len = u16::from_ne_bytes([attrs[pos], attrs[pos + 1]]) as usize;
        let ntype = u16::from_ne_bytes([attrs[pos + 2], attrs[pos + 3]]);
        if len < 4 || pos + len > attrs.len() {
            break;
        }
        let data = &attrs[pos + 4..pos + len];
        match ntype {
            NFQA_PACKET_HDR if data.len() >= 4 => {
                packet.packet_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            }
            NFQA_IFINDEX_INDEV if data.len() >= 4 => {
                packet.indev = Some(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]));
            }
            NFQA_IFINDEX_OUTDEV if data.len() >= 4 => {
                packet.outdev = Some(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]));
            }
            NFQA_PAYLOAD => {
                packet.payload = Some(data.to_vec());
            }
            NFQA_CAP_LEN if data.len() >= 4 => {
                packet.cap_len = Some(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]));
            }
            _ => {}
        }
        pos += align4(len);
    }

    Ok(NfMessage::Packet(packet))
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Drop impl: kernel auto-unbinds when the socket closes.
impl Drop for NfQueue {
    fn drop(&mut self) {
        let _ = self.sock.send(
            &self.config_msg(NFQNL_CFG_CMD_UNBIND, None, self.queue_num),
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align4_rounds_up() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
    }

    #[test]
    fn nla_encoding_aligns() {
        let mut buf = Vec::new();
        push_nla(&mut buf, NFQA_PACKET_HDR, &[1, 2, 3, 4, 5, 6, 7, 8]);
        // 8 data + 4 header = 12, aligned
        assert_eq!(buf.len(), 12);
        assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), 12);
        assert_eq!(u16::from_ne_bytes([buf[2], buf[3]]), NFQA_PACKET_HDR);
    }

    #[test]
    fn parses_packet_message() {
        // Build a minimal NFQNL_MSG_PACKET message by hand.
        let mut body = Vec::new();
        body.push(NFPROTO_INET);
        body.push(NFNETLINK_V0);
        body.extend_from_slice(&0u16.to_be_bytes()); // res_id
                                                     // NFQA_PACKET_HDR
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&0x11223344u32.to_be_bytes());
        hdr.extend_from_slice(&0x0800u16.to_be_bytes());
        hdr.push(1); // hook
        hdr.push(0);
        push_nla(&mut body, NFQA_PACKET_HDR, &hdr);
        // NFQA_PAYLOAD
        push_nla(&mut body, NFQA_PAYLOAD, &[0x45, 0x00, 0x00, 0x28]);
        // wrap in netlink header
        let mut msg = Vec::new();
        let total = 16 + body.len();
        msg.extend_from_slice(&(total as u32).to_ne_bytes());
        msg.extend_from_slice(&nfgenmsg_type(NFNL_SUBSYS_QUEUE, NFQNL_MSG_PACKET).to_ne_bytes());
        msg.extend_from_slice(&(netlink_packet_core::NLM_F_REQUEST as u16).to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&body);

        let parsed = parse_netfilter_message(&msg).unwrap();
        match parsed {
            NfMessage::Packet(p) => {
                assert_eq!(p.packet_id, 0x11223344);
                assert_eq!(p.payload.as_deref(), Some(&[0x45, 0x00, 0x00, 0x28][..]));
            }
            NfMessage::Other => panic!("expected packet"),
        }
    }
}

/// Hex dump helper for diagnostics.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
