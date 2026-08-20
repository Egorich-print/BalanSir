//! B4 strategy-set model (mission §6).
//!
//! This is the schema for a complete DPI-bypass strategy, expressed in JSON or
//! TOML, matching the classic b4/byedpi strategy format. A strategy-set has
//! four planes — `tcp`, `udp`, `fragmentation`, `faking` — plus `targets` and
//! `dns`. It is deliberately self-contained so the WebUI, the B4 config files
//! and the Discovery subsystem all speak one vocabulary.
//!
//! The `youtube` example from the mission parses 1:1:
//! ```json
//! {"name":"youtube","tcp":{"conn_bytes_limit":19,"seg2delay":20,"seg2delay_max":60,
//!  "syn_fake":false,"drop_sack":false,"syn_ttl":7,
//!  "incoming":{"mode":"off","min":14,"max":14,"fake_ttl":7,"fake_count":3,"strategy":"badsum"},
//!  "desync":{"mode":"off","ttl":7,"count":3,"post_desync":false},
//!  "win":{"mode":"off","values":[0,1460,8192,65535]},
//!  "duplicate":{"enabled":false,"count":3}},
//!  "udp":{"mode":"fake","fake_seq_length":6,"fake_len":64,"faking_strategy":"none",
//!  "dport_filter":"","filter_quic":"parse","filter_stun":true,"conn_bytes_limit":8,
//!  "seg2delay":10,"seg2delay_max":40},
//!  "fragmentation":{"strategy":"combo","reverse_order":true,"tlsrec_pos":0,
//!  "middle_sni":true,"sni_position":1,"oob_position":0,"oob_char":120,
//!  "seq_overlap_pattern":[],"combo":{"first_byte_split":true,"extension_split":true,
//!  "shuffle_mode":"full","first_delay_ms":30,"jitter_max_us":1000,"decoy_enabled":false,
//!  "decoy_snis":["ya.ru","vk.com","mail.ru","dzen.ru"]},
//!  "disorder":{"shuffle_mode":"full","min_jitter_us":1000,"max_jitter_us":3000}},
//!  "faking":{"sni":true,"ttl":8,"strategy":"pastseq","seq_offset":10000,
//!  "sni_seq_length":1,"sni_type":3,"custom_payload":"","payload_file":"",
//!  "tls_mod":[],"timestamp_decrease":600000,"sni_mutation":{"mode":"off",
//!  "grease_count":3,"padding_size":2048,"fake_ext_count":5,"fake_snis":[]},
//!  "tcp_md5":true},
//!  "targets":{"sni_domains":[],"ip":[],"geosite_categories":["youtube"],"geoip_categories":[]},
//!  "enabled":true,"dns":{"enabled":false,"target_dns":"","fragment_query":false}}
//! ```

use serde::{Deserialize, Serialize};

/// One strategy-set: all four planes plus targets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct B4Set {
    /// Optional stable id (uuid).
    #[serde(default)]
    pub id: Option<String>,
    /// Human name (e.g. "youtube", "hyperion").
    pub name: String,
    pub tcp: TcpPlane,
    pub udp: UdpPlane,
    pub fragmentation: FragmentationPlane,
    pub faking: FakingPlane,
    pub targets: Targets,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub dns: DnsPlane,
}

fn default_true() -> bool {
    true
}

/// TCP mutation plane.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TcpPlane {
    /// Kill the connection after N MB transferred (RST injection). 0 = off.
    pub conn_bytes_limit: u32,
    /// Delay subsequent segments by this many ms (0 = off).
    pub seg2delay: u64,
    /// Maximum extra delay added as jitter (ms).
    pub seg2delay_max: u64,
    /// Send a fake SYN before the real one.
    pub syn_fake: bool,
    /// Length of the fake SYN payload.
    pub syn_fake_len: u32,
    /// TTL to set on the SYN.
    pub syn_ttl: u8,
    /// Strip the SACK-permitted option.
    pub drop_sack: bool,
    pub incoming: IncomingPlane,
    pub desync: DesyncPlane,
    pub win: WinPlane,
    pub duplicate: DuplicatePlane,
}

/// Incoming fake-packet plane (badsum strategy: fake packets with a bad TCP
/// checksum sent to the remote to confuse DPI's state tracking).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IncomingPlane {
    /// `off` | `fake`.
    pub mode: String,
    pub min: u32,
    pub max: u32,
    pub fake_ttl: u8,
    pub fake_count: u32,
    /// `badsum` | `seq`.
    pub strategy: String,
}

/// TCP desync plane (offset the sequence numbers observed by DPI).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DesyncPlane {
    pub mode: String,
    pub ttl: u8,
    pub count: u32,
    pub post_desync: bool,
}

/// TCP window-scaling confusion plane.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WinPlane {
    pub mode: String,
    #[serde(default)]
    pub values: Vec<u32>,
}

/// TCP duplicate-segment plane.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DuplicatePlane {
    pub enabled: bool,
    pub count: u32,
}

/// UDP plane. `mode: "fake"` generates fake QUIC packets toward the target so
/// DPI stops tracking QUIC (forces the client to retry over TCP — the classic
/// YouTube bypass). `mode: "off"` leaves UDP alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UdpPlane {
    /// `off` | `fake`.
    pub mode: String,
    /// Length of the fake QUIC initial (sequence length bytes).
    pub fake_seq_length: u32,
    /// Payload length of each fake packet.
    pub fake_len: u32,
    /// `none` | `random` | `pastseq`.
    pub faking_strategy: String,
    /// Destination-port filter (empty = all).
    pub dport_filter: String,
    /// `disabled` | `parse`.
    pub filter_quic: String,
    pub filter_stun: bool,
    /// Kill the UDP "connection" (flow) after N MB of faked traffic.
    pub conn_bytes_limit: u32,
    pub seg2delay: u64,
    pub seg2delay_max: u64,
}

/// Fragmentation plane (TCP segment splitting so DPI cannot reassemble the
/// ClientHello / SNI).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FragmentationPlane {
    /// `combo` | `disorder` | `none`.
    pub strategy: String,
    pub reverse_order: bool,
    pub tlsrec_pos: u32,
    /// Split *inside* the SNI so no single fragment carries it whole.
    pub middle_sni: bool,
    /// Where the split lands relative to the SNI.
    pub sni_position: u32,
    pub oob_position: u32,
    /// Byte value for out-of-band padding.
    pub oob_char: u8,
    #[serde(default)]
    pub seq_overlap_pattern: Vec<u32>,
    pub combo: ComboPlane,
    pub disorder: DisorderPlane,
}

/// Combo fragmentation: split the first byte / extension blocks and shuffle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ComboPlane {
    /// Split the first byte of the TLS record into its own fragment.
    pub first_byte_split: bool,
    /// Split at the extensions boundary.
    pub extension_split: bool,
    /// `full` | `none`.
    pub shuffle_mode: String,
    pub first_delay_ms: u64,
    pub jitter_max_us: u64,
    /// Send decoy SNI-lookalike packets first (presented in TLS) to confuse DPI.
    pub decoy_enabled: bool,
    #[serde(default)]
    pub decoy_snis: Vec<String>,
}

/// Packet-order disorder plane (jittered reordering).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DisorderPlane {
    pub shuffle_mode: String,
    pub min_jitter_us: u64,
    pub max_jitter_us: u64,
}

/// Faking plane (SNI/TLS fingerprint spoofing).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FakingPlane {
    pub sni: bool,
    pub ttl: u8,
    /// `pastseq` | `none`.
    pub strategy: String,
    /// Sequence offset to jump the SNI by (fake).
    pub seq_offset: u32,
    pub sni_seq_length: u32,
    pub sni_type: u32,
    #[serde(default)]
    pub custom_payload: String,
    #[serde(default)]
    pub payload_file: String,
    #[serde(default)]
    pub tls_mod: Vec<u32>,
    pub timestamp_decrease: u64,
    pub sni_mutation: SniMutationPlane,
    pub tcp_md5: bool,
}

/// SNI mutation plane (grease / padding / fake extensions).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SniMutationPlane {
    pub mode: String,
    pub grease_count: u32,
    pub padding_size: u32,
    pub fake_ext_count: u32,
    #[serde(default)]
    pub fake_snis: Vec<String>,
}

/// Target selection: which traffic a strategy applies to.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Targets {
    /// Literal SNI domains.
    #[serde(default)]
    pub sni_domains: Vec<String>,
    /// Literal destination IPs.
    #[serde(default)]
    pub ip: Vec<String>,
    /// v2fly domain-list-community geosite categories (e.g. ["youtube"]).
    #[serde(default)]
    pub geosite_categories: Vec<String>,
    /// geoip categories (e.g. ["cloudflare"]).
    #[serde(default)]
    pub geoip_categories: Vec<String>,
}

/// DNS handling plane (optional DoH override / fragment).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsPlane {
    pub enabled: bool,
    #[serde(default)]
    pub target_dns: String,
    pub fragment_query: bool,
}

/// Statistics about a strategy-set (populated by Discovery / the engine).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct B4SetStats {
    pub manual_domains: usize,
    pub manual_ips: usize,
    pub geosite_domains: usize,
    pub geoip_ips: usize,
    pub total_domains: usize,
    pub total_ips: usize,
    #[serde(default)]
    pub geosite_category_breakdown: std::collections::BTreeMap<String, usize>,
    #[serde(default)]
    pub geoip_category_breakdown: std::collections::BTreeMap<String, usize>,
}

impl B4Set {
    /// Whether this set wants UDP interception at all.
    pub fn wants_udp(&self) -> bool {
        self.enabled && self.udp.mode == "fake"
    }

    /// Whether this set wants TCP interception.
    pub fn wants_tcp(&self) -> bool {
        self.enabled
    }

    /// The target domains, expanded from literals. Geosite categories are not
    /// expanded here (that needs the geosite store) — callers merge.
    pub fn literal_domains(&self) -> Vec<String> {
        self.targets.sni_domains.clone()
    }

    /// The target IPs, expanded from literals.
    pub fn literal_ips(&self) -> Vec<String> {
        self.targets.ip.clone()
    }

    /// Whether this set references any geosite categories.
    pub fn has_geosite(&self) -> bool {
        !self.targets.geosite_categories.is_empty()
    }

    /// Whether this set references any geoip categories.
    pub fn has_geoip(&self) -> bool {
        !self.targets.geoip_categories.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mission_youtube_set() {
        let json = r#"{
          "id":"f506c73d-9b25-4be0-b117-c9d70591befe",
          "name":"youtube",
          "tcp":{"conn_bytes_limit":19,"seg2delay":20,"seg2delay_max":60,"syn_fake":false,"syn_fake_len":0,"syn_ttl":7,"drop_sack":false,"incoming":{"mode":"off","min":14,"max":14,"fake_ttl":7,"fake_count":3,"strategy":"badsum"},"desync":{"mode":"off","ttl":7,"count":3,"post_desync":false},"win":{"mode":"off","values":[0,1460,8192,65535]},"duplicate":{"enabled":false,"count":3}},
          "udp":{"mode":"fake","fake_seq_length":6,"fake_len":64,"faking_strategy":"none","dport_filter":"","filter_quic":"parse","filter_stun":true,"conn_bytes_limit":8,"seg2delay":10,"seg2delay_max":40},
          "fragmentation":{"strategy":"combo","reverse_order":true,"tlsrec_pos":0,"middle_sni":true,"sni_position":1,"oob_position":0,"oob_char":120,"seq_overlap_pattern":[],"combo":{"first_byte_split":true,"extension_split":true,"shuffle_mode":"full","first_delay_ms":30,"jitter_max_us":1000,"decoy_enabled":false,"decoy_snis":["ya.ru","vk.com","mail.ru","dzen.ru"]},"disorder":{"shuffle_mode":"full","min_jitter_us":1000,"max_jitter_us":3000}},
          "faking":{"sni":true,"ttl":8,"strategy":"pastseq","seq_offset":10000,"sni_seq_length":1,"sni_type":3,"custom_payload":"","payload_file":"","tls_mod":[],"timestamp_decrease":600000,"sni_mutation":{"mode":"off","grease_count":3,"padding_size":2048,"fake_ext_count":5,"fake_snis":[]},"tcp_md5":true},
          "targets":{"sni_domains":[],"ip":[],"geosite_categories":["youtube"],"geoip_categories":[]},
          "enabled":true,
          "dns":{"enabled":false,"target_dns":"","fragment_query":false}
        }"#;
        let set: B4Set = serde_json::from_str(json).unwrap();
        assert_eq!(set.name, "youtube");
        assert_eq!(
            set.id.as_deref(),
            Some("f506c73d-9b25-4be0-b117-c9d70591befe")
        );
        assert!(set.enabled);
        assert!(set.wants_udp());
        assert_eq!(set.tcp.conn_bytes_limit, 19);
        assert_eq!(set.tcp.seg2delay, 20);
        assert_eq!(set.tcp.syn_ttl, 7);
        assert!(!set.tcp.drop_sack);
        assert_eq!(set.tcp.incoming.mode, "off");
        assert_eq!(set.tcp.desync.mode, "off");
        assert_eq!(set.tcp.win.values, vec![0, 1460, 8192, 65535]);
        assert_eq!(set.udp.mode, "fake");
        assert_eq!(set.udp.filter_quic, "parse");
        assert_eq!(set.fragmentation.strategy, "combo");
        assert!(set.fragmentation.middle_sni);
        assert_eq!(set.fragmentation.combo.first_delay_ms, 30);
        assert_eq!(set.fragmentation.combo.decoy_snis.len(), 4);
        assert_eq!(set.faking.strategy, "pastseq");
        assert_eq!(set.faking.seq_offset, 10000);
        assert!(set.faking.tcp_md5);
        assert_eq!(set.targets.geosite_categories, vec!["youtube"]);
        assert!(set.targets.geoip_categories.is_empty());
    }

    #[test]
    fn parses_hyperion_set_with_geoip() {
        let json = r#"{
          "name":"hyperion",
          "tcp":{"conn_bytes_limit":19,"seg2delay":20,"seg2delay_max":90,"syn_fake":false,"syn_fake_len":0,"syn_ttl":7,"drop_sack":false,"incoming":{"mode":"off","min":14,"max":14,"fake_ttl":7,"fake_count":3,"strategy":"badsum"},"desync":{"mode":"off","ttl":7,"count":3,"post_desync":false},"win":{"mode":"off","values":[0,1460,8192,65535]},"duplicate":{"enabled":false,"count":3}},
          "udp":{"mode":"fake","fake_seq_length":6,"fake_len":64,"faking_strategy":"none","dport_filter":"","filter_quic":"disabled","filter_stun":true,"conn_bytes_limit":8,"seg2delay":0,"seg2delay_max":0},
          "fragmentation":{"strategy":"combo","reverse_order":true,"tlsrec_pos":0,"middle_sni":true,"sni_position":1,"oob_position":0,"oob_char":120,"seq_overlap_pattern":[],"combo":{"first_byte_split":true,"extension_split":true,"shuffle_mode":"full","first_delay_ms":30,"jitter_max_us":1500,"decoy_enabled":false,"decoy_snis":["ya.ru","vk.com","mail.ru","dzen.ru"]},"disorder":{"shuffle_mode":"full","min_jitter_us":1000,"max_jitter_us":3000}},
          "faking":{"sni":true,"ttl":8,"strategy":"pastseq","seq_offset":10000,"sni_seq_length":1,"sni_type":4,"custom_payload":"","payload_file":"captures/tls_gosuslugi_ru.bin","tls_mod":[],"timestamp_decrease":600000,"sni_mutation":{"mode":"off","grease_count":3,"padding_size":2048,"fake_ext_count":5,"fake_snis":[]},"tcp_md5":true},
          "targets":{"sni_domains":["kinopub.online","linuxserver.io","euronews.com","shikimori.one","proton.me"],"ip":[],"geosite_categories":["cloudflare","ru-blocked","meta","discord","kinopub","youtube","twitter","protonmail"],"geoip_categories":["cloudflare","digitalocean","contabo","akamai","amazon"]},
          "enabled":true,
          "dns":{"enabled":false,"target_dns":"","fragment_query":false}
        }"#;
        let set: B4Set = serde_json::from_str(json).unwrap();
        assert_eq!(set.name, "hyperion");
        assert_eq!(set.targets.sni_domains.len(), 5);
        assert_eq!(set.targets.geosite_categories.len(), 8);
        assert_eq!(set.targets.geoip_categories.len(), 5);
        assert_eq!(set.udp.filter_quic, "disabled");
        assert_eq!(set.faking.sni_type, 4);
        assert_eq!(set.faking.payload_file, "captures/tls_gosuslugi_ru.bin");
    }

    #[test]
    fn defaults_when_empty() {
        let set = B4Set::default();
        assert!(!set.enabled || set.tcp.conn_bytes_limit == 0);
        assert!(!set.wants_udp());
    }

    #[test]
    fn literal_targets() {
        let set = B4Set {
            name: "x".into(),
            targets: Targets {
                sni_domains: vec!["a.com".into()],
                ip: vec!["1.2.3.4".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(set.literal_domains(), vec!["a.com"]);
        assert_eq!(set.literal_ips(), vec!["1.2.3.4"]);
        assert!(!set.has_geosite());
        assert!(!set.has_geoip());
    }
}
