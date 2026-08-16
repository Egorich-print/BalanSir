use balansir_common::event_bus::BoundedEventBus;
use balansir_common::ipc::{IpcMessage, IpcServerConnection, MsgType};
use balansir_common::metrics::SharedMetrics;
use balansir_common::{DesiredState, DriverId, Result};
use balansir_control::ReconcileReason;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

use balansir_daemon::driver::factory::ConfiguredFactory;
use balansir_daemon::driver::health::TierTracker;
use balansir_daemon::driver::lifecycle::{DriverIntent, DriverLifecycleManager};
use balansir_daemon::driver::ComponentDriver;
use balansir_daemon::reconciliation::{ExecutorClient, Reconciler, ReconcilerConfig};

const SOCKET_PATH: &str = "/run/balansir/daemon.sock";
const SOCKET_PERMS: u32 = 0o600;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("balansir_daemon=debug,balansir_b4=debug")
        .init();

    info!("BalanSir Daemon starting");

    let socket_path = Path::new(SOCKET_PATH);
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    remove_stale_socket(socket_path)?;

    let listener = UnixListener::bind(socket_path)?;
    tokio::fs::set_permissions(socket_path, Permissions::from_mode(SOCKET_PERMS)).await?;
    info!("Listening on {} (mode {:#o})", SOCKET_PATH, SOCKET_PERMS);

    // Driver lifecycle state machine (ADR-011). Real driver configs are wired
    // via the typed ConfiguredFactory (M3.5); until a config source is loaded
    // the registry is empty and every Start fails honestly as a tracked Failed
    // slot.
    let lifecycle: Arc<tokio::sync::Mutex<DriverLifecycleManager>> =
        Arc::new(tokio::sync::Mutex::new(DriverLifecycleManager::new(
            Box::new(ConfiguredFactory::empty()),
        )));

    // M3.3 observability: shared metrics + event bus + tier tracker, fed by the
    // orchestration layer (NOT by the lifecycle manager itself, per ADR-012).
    let metrics = Arc::new(SharedMetrics::new());
    let events: Arc<BoundedEventBus> = Arc::new(BoundedEventBus::new(1024));
    let tracker = Arc::new(tokio::sync::Mutex::new(TierTracker::default()));

    // M3.4.1 production control plane: the daemon binary now drives the real
    // Coordinator -> BasicPlanner -> plan -> execution-adapter -> ActualState
    // path. Per ADR-013 the daemon is the commander: it sends operations to
    // the privileged executor server via ExecutorClient. If the executor is
    // unreachable the reconcile fails and rolls back — ActualState is never
    // faked. Driver lifecycle (above) remains a separate path.
    //
    // P7.2.1 (ADR-027) startup configuration recovery: BALANSIR_CONFIG is
    // loaded and strictly validated BEFORE the first reconcile, so a reboot
    // restores the last accepted DesiredState without an operator reload. A
    // malformed or pointed-at-but-missing config is a fatal startup error —
    // never silently substituted with an empty state. No env var means start
    // empty (dev/first-boot).
    let startup_desired =
        match balansir_daemon::startup::load_startup_desired(std::env::var("BALANSIR_CONFIG")) {
            Ok(balansir_daemon::startup::StartupDesired::Loaded(state)) => {
                info!(rules = state.rules.len(), "Startup config loaded");
                state
            }
            Ok(balansir_daemon::startup::StartupDesired::Empty) => {
                warn!("No BALANSIR_CONFIG set; starting empty (no enforcement until reload)");
                balansir_common::DesiredState::default()
            }
            Err(e) => {
                error!("Startup config rejected: {e}");
                std::process::exit(1);
            }
        };

    let executor_client = Arc::new(ExecutorClient::default());
    let reconciler = Arc::new(Reconciler::new(
        startup_desired.clone(),
        executor_client.clone(),
        ReconcilerConfig::default(),
    ));
    // P7.2.1 (ADR-027) + P4.8 (ADR-021): record the raw desired state and its
    // fingerprint so `balansir-cli fingerprint` reflects exactly what was
    // loaded at boot, and the DNS resync (P6) has the authored state to
    // recompile. The flow compiler is registered below, after this.
    reconciler.set_desired(startup_desired).await;
    // A2: seed ActualState from the executor's kernel inventory so any rule
    // left behind by an ack-gap/executor restart is reconciled (removed if not
    // desired). Non-authoritative — the daemon still decides what should be.
    if let Err(e) = reconciler.sync_actual_from_executor().await {
        warn!("Could not read executor inventory (will reconcile anyway): {e}");
    }
    match reconciler.reconcile().await {
        Ok(()) => info!("Initial reconcile: no changes required"),
        Err(e) => warn!(
            "Initial reconcile incomplete (executor unreachable or op failed): {}",
            e
        ),
    }

    // Gateway port roles + WAN MAC cloning (mission §12–13). The roles are
    // explicit configuration — never autodetection. When configured, the
    // daemon validates them against the live interface snapshot, then clones
    // the router's WAN MAC onto the provider-facing port via the executor. A
    // fail-closed daemon refuses to run a misconfigured gateway.
    apply_network_config(&executor_client).await;

    // P4.1 (ADR-020) ownership loop: converge Desired → kernel on a cadence,
    // re-seeding ActualState from the executor inventory periodically so
    // external kernel edits and executor restarts are discovered, not just
    // startup orphans.
    let loop_reconciler = Arc::clone(&reconciler);
    tokio::spawn(async move {
        loop_reconciler.run_loop().await;
    });

    // P6 (ADR-023) DNS plane + P7.2.2 (ADR-028) shared DNS observation
    // authority: ONE registry is the single DNS observation truth. It feeds
    // both the flow compiler (DNS resync / domain → IP compilation) and the
    // B4 observer — so a DNS observation change seen by P6 is the same change
    // B4 sees. There is no second `DnsRegistry` in the production path.
    let dns_registry = std::sync::Arc::new(balansir_daemon::reconciliation::DnsRegistry::new());
    let compiler = balansir_daemon::reconciliation::FlowCompiler::new((*dns_registry).clone());
    reconciler.with_flow_compiler(compiler).await;
    // Metrics: attach the shared instance to the reconciler so reconciliation
    // outcomes update the same counters/gauges the API and IPC expose (one
    // metrics system, ADR-009/ADR-012).
    reconciler.attach_metrics(Arc::clone(&metrics)).await;

    // P6 (ADR-023): DNS observation source. When BALANSIR_DNS_CONFIG points at
    // a forwarder config, start the DNS forwarder driver with the SAME shared
    // registry the flow compiler and B4 observer read — real DNS traffic then
    // feeds policy compilation and B4 DNS observation. The driver is inert
    // unless configured (and must stay alive for the daemon's lifetime, hence
    // the holder below).
    #[cfg(feature = "dns")]
    let dns_forwarder: std::sync::Arc<balansir_daemon::dns::DnsForwarderDriver> = {
        let dns_path = std::env::var("BALANSIR_DNS_CONFIG").ok();
        let driver = dns_path
            .and_then(|path| balansir_daemon::dns::DnsForwarderConfig::from_file(&path).ok())
            .map(|dns_cfg| {
                let mut driver = balansir_daemon::dns::DnsForwarderDriver::new(
                    balansir_common::DriverId::DnsForwarder,
                    dns_cfg,
                );
                driver.attach_registry(Arc::clone(&dns_registry));
                driver
            });
        match driver {
            Some(mut driver) => match driver.start().await {
                Ok(()) => {
                    info!("DNS forwarder started");
                    Arc::new(driver)
                }
                Err(e) => {
                    warn!("DNS forwarder failed to start: {e}");
                    Arc::new(balansir_daemon::dns::DnsForwarderDriver::new(
                        balansir_common::DriverId::DnsForwarder,
                        balansir_daemon::dns::DnsForwarderConfig::default(),
                    ))
                }
            },
            None => Arc::new(balansir_daemon::dns::DnsForwarderDriver::new(
                balansir_common::DriverId::DnsForwarder,
                balansir_daemon::dns::DnsForwarderConfig::default(),
            )),
        }
    };
    #[cfg(not(feature = "dns"))]
    let dns_forwarder: std::sync::Arc<balansir_daemon::dns::DnsForwarderDriver> =
        Arc::new(balansir_daemon::dns::DnsForwarderDriver::new(
            balansir_common::DriverId::DnsForwarder,
            balansir_daemon::dns::DnsForwarderConfig::default(),
        ));

    let dns_loop_reconciler = Arc::clone(&reconciler);
    tokio::spawn(async move {
        dns_loop_reconciler.dns_loop().await;
    });
    // HTTP/SSE management plane: subsystem managers + REST/SSE endpoints,
    // served by the daemon itself. Enabled via BALANSIR_API_BIND or the
    // `[api]` section of BALANSIR_CONFIG; the WebUI talks to this.
    let api_bind = balansir_daemon::server::api_bind();
    let mut b4_control: Option<balansir_daemon::b4_manager::B4ManagerHandle> = None;
    // Keep the subsystem manager alive past the API spawn so the graceful
    // shutdown path can stop the DPI engine / remove its queue rules.
    let mut manager_cleanup: Option<std::sync::Arc<balansir_daemon::subsystems::SubsystemManager>> =
        None;
    if !api_bind.trim().is_empty() {
        // One shared snapshot + event bus for QoS / interfaces / Tailscale / B4.
        let manager = std::sync::Arc::new(balansir_daemon::subsystems::SubsystemManager::new(
            executor_client.clone(),
        ));
        manager_cleanup = Some(std::sync::Arc::clone(&manager));
        manager
            .set_interface_filter(std::env::var("BALANSIR_INTERFACES").unwrap_or_default())
            .await;

        // P7.2 (ADR-026) B4 component: policy-controlled connectivity
        // adaptation. Loads the optional B4 config (BALANSIR_B4_CONFIG). The
        // B4Manager runs the engine per configured flow, executes MTU/DNS-path
        // decisions via the ExecutorAdapter, converges executor-reported MTU to
        // the daemon's intent (P4.1 ownership), and publishes B4 state into the
        // SAME subsystem snapshot + event bus the WebUI reads — one component,
        // one vocabulary.
        if let Ok(b4_path) = std::env::var("BALANSIR_B4_CONFIG") {
            match balansir_daemon::b4_engine::config::B4Toml::from_file(&b4_path) {
                Ok(b4_cfg) => {
                    // P7.2.2 (ADR-028): reuse the SAME shared registry that
                    // feeds the P6 flow compiler — one DNS observation truth.
                    match balansir_daemon::b4_manager::B4Manager::from_toml(
                        &b4_path,
                        &b4_cfg,
                        Arc::clone(&dns_registry),
                        reconciler.executor_adapter(),
                        manager.snapshot(),
                        manager.event_sender(),
                    ) {
                        Ok(b4_manager) => {
                            b4_control = Some(b4_manager.handle());
                            tokio::spawn(async move {
                                b4_manager.run_loop(10).await;
                            });
                            info!("B4 engine started from {b4_path}");
                        }
                        Err(e) => {
                            warn!("B4 config {b4_path} policy rejected: {e} (engine disabled)")
                        }
                    }
                }
                Err(e) => warn!("B4 config {b4_path} rejected: {e} (engine disabled)"),
            }
        }

        // DPI-bypass (Rust-native NFQUEUE engine). Loads the optional
        // BALANSIR_DPI_CONFIG (profiles/sets); the engine intercepts matching
        // TCP via NFQUEUE and applies per-domain bypass strategies. The
        // manager installs/removes the nft queue rules through the executor so
        // a stopped engine never leaves a blackhole (rules render `bypass`).
        if let Ok(dpi_path) = std::env::var("BALANSIR_DPI_CONFIG") {
            match balansir_daemon::b4_dpi::DpiManager::new_with_executor(
                &dpi_path,
                Some(reconciler.executor_adapter()),
            ) {
                Ok(dpi_manager) => {
                    let dpi = std::sync::Arc::new(dpi_manager);
                    match dpi.start().await {
                        Ok(()) => {
                            manager.set_dpi(dpi.clone()).await;
                            info!("DPI-bypass engine started from {dpi_path}");
                        }
                        Err(e) => {
                            warn!("DPI-bypass engine start failed ({e}); engine disabled");
                        }
                    }
                }
                Err(e) => warn!("DPI-bypass config {dpi_path} rejected: {e} (disabled)"),
            }
        }

        let loop_manager = std::sync::Arc::clone(&manager);
        tokio::spawn(async move {
            loop_manager.run_loop().await;
        });

        // Xray transport component (BALANSIR_XRAY_CONFIG): endpoint profiles,
        // active process, failover/rotation/recovery. Not started by default —
        // the transport is only active when the operator configures it.
        #[cfg(feature = "xray")]
        let xray_control: Option<balansir_daemon::xray_manager::XrayManagerHandle> = {
            match std::env::var("BALANSIR_XRAY_CONFIG") {
                Ok(xray_path) => {
                    match balansir_daemon::xray_manager::XrayToml::from_file(&xray_path) {
                        Ok(xray_cfg) => {
                            match balansir_daemon::xray_manager::XrayManager::from_toml(
                                &xray_cfg,
                                manager.snapshot(),
                                manager.event_sender(),
                            ) {
                                Ok(xray_manager) => {
                                    let handle = xray_manager.handle();
                                    tokio::spawn(async move {
                                        xray_manager.run_loop(10).await;
                                    });
                                    info!("Xray component started from {xray_path}");
                                    Some(handle)
                                }
                                Err(e) => {
                                    warn!("Xray config {xray_path} rejected: {e} (component disabled)");
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Xray config {xray_path} rejected: {e} (component disabled)");
                            None
                        }
                    }
                }
                Err(_) => None,
            }
        };
        #[cfg(not(feature = "xray"))]
        let xray_control: Option<()> = None;

        // VPN alternative-path pool (BALANSIR_VPN_CONFIG). The pool is the
        // authoritative path decision; it drives the Xray manager as a
        // consumer. When Xray is not configured, the pool still runs and
        // tracks health/selection with a no-op consumer (observability only).
        #[cfg(feature = "xray")]
        {
            if let Ok(vpn_path) = std::env::var("BALANSIR_VPN_CONFIG") {
                match balansir_daemon::vpn_manager::VpnToml::from_file(&vpn_path) {
                    Ok(vpn_cfg) => {
                        let consumer: std::sync::Arc<
                            dyn balansir_daemon::vpn_manager::XrayConsumer,
                        > = match &xray_control {
                            Some(handle) => {
                                let h = handle.clone();
                                std::sync::Arc::new(
                                    balansir_daemon::vpn_manager::PoolXrayConsumer::new(
                                        move |profile: Option<&balansir_vpn::VpnProfile>| {
                                            let h = h.clone();
                                            let profile = profile.cloned();
                                            tokio::spawn(async move {
                                                h.apply_pool_profile(profile).await;
                                            });
                                        },
                                    ),
                                )
                            }
                            None => {
                                std::sync::Arc::new(balansir_daemon::vpn_manager::NoopXrayConsumer)
                            }
                        };
                        match balansir_daemon::vpn_manager::VpnManager::new(
                            vpn_cfg,
                            manager.snapshot(),
                            manager.event_sender(),
                            consumer,
                        ) {
                            Ok(vpn) => {
                                let vpn = std::sync::Arc::new(vpn);
                                let handle = vpn.handle();
                                manager.set_vpn_handle(handle).await;
                                let loop_vpn = std::sync::Arc::clone(&vpn);
                                tokio::spawn(async move {
                                    loop_vpn.run_loop().await;
                                });
                                info!("VPN pool started from {vpn_path}");
                            }
                            Err(e) => warn!("VPN pool config {vpn_path} rejected: {e}"),
                        }
                    }
                    Err(e) => warn!("VPN pool config {vpn_path} rejected: {e}"),
                }
            }
        }
        #[cfg(not(feature = "xray"))]
        {
            let _ = xray_control;
        }

        // DNS VPN proxy monitoring task: updates DNS forwarder's SOCKS5 proxy
        // based on path_decision from SubsystemManager. When path_decision
        // indicates VpnActive, DNS queries are routed through Xray's SOCKS5
        // proxy via SOCKS5 UDP associate.
        let dns_forwarder_clone = Arc::clone(&dns_forwarder);
        let manager_snapshot = manager.snapshot();
        #[cfg(feature = "xray")]
        let xray_socks_port = xray_control
            .as_ref()
            .map(|h| h.socks_port())
            .unwrap_or(10808);
        #[cfg(not(feature = "xray"))]
        let xray_socks_port = 10808u16;
        let _manager_snapshot = manager.snapshot(); // for potential future use
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            let mut last_vpn_active = false;
            loop {
                interval.tick().await;
                let snap = manager_snapshot.read().await;
                let vpn_active = snap.vpn_pool.active.is_some() && !snap.vpn_pool.paused;
                drop(snap);

                if vpn_active != last_vpn_active {
                    if vpn_active {
                        let proxy_addr = format!("127.0.0.1:{}", xray_socks_port).parse().unwrap();
                        dns_forwarder_clone.set_vpn_proxy(Some(proxy_addr));
                        info!(
                            "DNS forwarder VPN proxy enabled (SOCKS5 127.0.0.1:{})",
                            xray_socks_port
                        );
                    } else {
                        dns_forwarder_clone.set_vpn_proxy(None);
                        info!("DNS forwarder VPN proxy disabled");
                    }
                    last_vpn_active = vpn_active;
                }
            }
        });

        let api_bind_clone = api_bind.clone();
        let api_reconciler = Arc::clone(&reconciler);
        let api_metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Err(e) = balansir_daemon::server::start_api_server(
                manager,
                api_reconciler,
                api_metrics,
                b4_control,
                #[cfg(feature = "xray")]
                xray_control,
                api_bind_clone,
            )
            .await
            {
                error!("API server error: {e}");
            }
        });
        info!("API enabled on {api_bind}");
    }

    // Setup signal handlers
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        // Authenticate peer via SO_PEERCRED
                        match IpcServerConnection::accept(stream).await {
                            Ok(conn) => {
                                info!("Executor connected (UID: {})", conn.peer_uid());
                                let lifecycle = Arc::clone(&lifecycle);
                                let metrics = Arc::clone(&metrics);
                                let events = Arc::clone(&events);
                                let tracker = Arc::clone(&tracker);
                                let reconciler = Arc::clone(&reconciler);
                                tokio::spawn(handle_connection(
                                    conn,
                                    lifecycle,
                                    metrics,
                                    events,
                                    tracker,
                                    reconciler,
                                ));
                            }
                            Err(e) => {
                                warn!("Authentication failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                    }
                }
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully...");
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down gracefully...");
                break;
            }
        }
    }

    // Cleanup
    info!("Cleaning up...");
    // Stop the DPI engine and remove its queue rules first so no NFQUEUE
    // interception rule is left behind (never a blackhole after restart).
    if let Some(manager) = manager_cleanup {
        manager.stop_dpi().await;
    }
    if socket_path.exists() {
        if let Err(e) = tokio::fs::remove_file(socket_path).await {
            warn!("Failed to remove socket: {}", e);
        }
    }

    info!("BalanSir Daemon stopped");
    Ok(())
}

/// Apply the gateway port-role configuration and WAN MAC cloning (mission
/// §12–13) at startup.
///
/// Fail-closed: when roles are configured but invalid against the live
/// interface snapshot, the daemon logs the exact reason and exits — a gateway
/// that guesses WAN/LAN must not run. WAN MAC is resolved in order: explicit
/// `wan_mac`, then auto-learned L2 peer on the LAN port; when neither is
/// available the MAC is left untouched with a warning (never a guess).
async fn apply_network_config(executor: &Arc<ExecutorClient>) {
    use balansir_daemon::network_config::{learn_lan_peer_mac, NetworkConfig};

    let config = match NetworkConfig::load() {
        Ok(c) => c,
        Err(e) => {
            error!("Network config rejected: {e}");
            std::process::exit(1);
        }
    };
    // No roles configured → gateway mode off; nothing to do.
    if config.wan_interface.is_none() && config.lan_interface.is_none() {
        return;
    }

    // Fetch the live interface snapshot through the executor (netlink). A
    // failure here is fatal: we cannot validate roles without it, and running
    // a gateway with unvalidated roles is the exact failure mode we forbid.
    let interfaces = match executor.interface_info("").await {
        Ok(infos) => infos,
        Err(e) => {
            error!("Network config: could not read interfaces from executor: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = config.validate(&interfaces) {
        error!("{e}");
        std::process::exit(1);
    }

    let wan = config.wan_interface.as_deref().unwrap_or_default();
    let lan = config.lan_interface.as_deref().unwrap_or_default();

    // Link state is informational at startup: the provider cable may not be
    // plugged yet. A link-down port is a warning, not a fatal error — the roles
    // themselves are still valid.
    for (role, name) in [("wan", wan), ("lan", lan)] {
        let up = interfaces
            .iter()
            .find(|i| i.name == name)
            .map(|i| i.link_up)
            .unwrap_or(false);
        if !up {
            warn!(
                role,
                interface = name,
                "Gateway port is down (carrier absent); check cabling"
            );
        }
    }

    if !config.cloning_enabled() {
        info!(
            wan,
            lan, "Gateway roles configured; WAN MAC cloning disabled"
        );
    } else {
        // Resolve the WAN MAC to clone: explicit config wins, then the
        // auto-learned L2 peer on the LAN port (the router). No result → warn
        // and do not change.
        let mac = config.wan_mac.clone().or_else(|| learn_lan_peer_mac(lan));
        let Some(mac) = mac else {
            warn!(
                wan,
                lan,
                "WAN MAC cloning enabled but no wan_mac configured and no LAN peer MAC learned; leaving WAN MAC unchanged"
            );
            return;
        };

        match executor.interface_set_mac(wan, &mac).await {
            Ok(result) => info!(
                wan,
                cloned_mac = result.current_mac.as_deref().unwrap_or_default(),
                hardware = result.hardware_mac.as_deref().unwrap_or_default(),
                "WAN MAC cloned"
            ),
            Err(e) => warn!("WAN MAC cloning on {wan} failed: {e}"),
        }
    }

    // Gateway datapath: NAT, IP forwarding, conntrack and the management
    // firewall. This is a real datapath (not an IPC declaration): the executor
    // renders and applies nftables MASQUERADE + conntrack + input rules and
    // sets net.ipv4.ip_forward. A failure is fatal — a gateway without NAT or
    // with management exposed to WAN must not run.
    let gateway_cfg = balansir_common::gateway::GatewayConfig {
        wan_interface: wan.to_string(),
        lan_interface: lan.to_string(),
        lan_subnet: config.lan_subnet.clone(),
    };
    if let Err(e) = gateway_cfg.validate() {
        error!("{e}");
        std::process::exit(1);
    }
    match executor.gateway_apply(&gateway_cfg).await {
        Ok(result) => info!("Gateway datapath applied: {}", result.detail),
        Err(e) => {
            error!("Gateway datapath apply failed: {e}");
            std::process::exit(1);
        }
    }

    // UPnP/IGD: SSDP + SOAP control point on the LAN. The IGD is LAN-only
    // (source-checked against lan_subnet); mappings are applied as DNAT rules
    // through the executor. WAN UPnP is blocked by the management firewall
    // (input policy drop) and by the IGD's own LAN-subnet source check.
    let lan_ip = interfaces
        .iter()
        .find(|i| i.name == lan)
        .and_then(|i| i.ipv4.first().cloned())
        .and_then(|ip| ip.parse::<std::net::IpAddr>().ok());
    match lan_ip {
        Some(lan_ip) => {
            let upnp_port = std::env::var("BALANSIR_UPNP_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3721);
            let upnp = std::sync::Arc::new(balansir_daemon::upnp::UpnpManager::new(
                Some(executor.clone()),
                lan_ip,
                &config.lan_subnet,
                wan,
                upnp_port,
            ));
            let upnp_task = std::sync::Arc::clone(&upnp);
            tokio::spawn(async move {
                upnp_task.run().await;
            });
            info!(
                lan_ip = %lan_ip,
                port = upnp_port,
                "UPnP/IGD started on LAN"
            );
        }
        None => warn!("UPnP/IGD disabled: no IPv4 address found for LAN interface {lan}"),
    }
}

async fn handle_connection(
    mut conn: IpcServerConnection,
    lifecycle: Arc<tokio::sync::Mutex<DriverLifecycleManager>>,
    metrics: Arc<SharedMetrics>,
    events: Arc<BoundedEventBus>,
    tracker: Arc<tokio::sync::Mutex<TierTracker>>,
    reconciler: Arc<Reconciler>,
) {
    loop {
        match conn.recv().await {
            Ok(msg) => {
                let response = handle_message(
                    &msg,
                    Arc::clone(&lifecycle),
                    &metrics,
                    &events,
                    &tracker,
                    &reconciler,
                )
                .await;
                if let Err(e) = conn.send(&response).await {
                    error!("Send error: {}", e);
                    break;
                }
            }
            Err(e) => {
                error!("Recv error: {}", e);
                break;
            }
        }
    }
}

/// Payload of a driver message: a postcard-encoded `DriverId`.
fn driver_id_from_payload(msg: &IpcMessage) -> Option<DriverId> {
    postcard::from_bytes(&msg.payload).ok()
}

/// Reconcile tier tracking after any lifecycle-affecting operation. Emits
/// `ComponentHealthChanged` on the bus and updates gauges; tier changes are
/// pushed only when the tier actually differs (ADR-012).
async fn refresh_tiers(
    lifecycle: &tokio::sync::Mutex<DriverLifecycleManager>,
    metrics: &SharedMetrics,
    events: &BoundedEventBus,
    tracker: &tokio::sync::Mutex<TierTracker>,
) {
    let mut tracker_guard = tracker.lock().await;
    let manager = lifecycle.lock().await;
    tracker_guard.reconcile(&manager, metrics, events);
}

async fn handle_message(
    msg: &IpcMessage,
    lifecycle: Arc<tokio::sync::Mutex<DriverLifecycleManager>>,
    metrics: &SharedMetrics,
    events: &BoundedEventBus,
    tracker: &tokio::sync::Mutex<TierTracker>,
    reconciler: &Reconciler,
) -> IpcMessage {
    match msg.msg_type {
        MsgType::HealthCheck => {
            info!("Health check requested");
            IpcMessage::response_ok(msg.correlation_id)
        }
        MsgType::GetMetrics => {
            let body = metrics.encode_metrics().into_bytes();
            IpcMessage::response_data(msg.correlation_id, body)
        }
        MsgType::StartDriver | MsgType::RestartDriver => {
            let Some(id) = driver_id_from_payload(msg) else {
                return IpcMessage::response_error(msg.correlation_id, "Invalid driver id");
            };
            let fingerprint = id.as_u32() as u64;
            let intent = DriverIntent {
                id,
                action: if msg.msg_type == MsgType::RestartDriver {
                    balansir_common::DriverAction::Restart
                } else {
                    balansir_common::DriverAction::Start
                },
                fingerprint,
            };
            let failed = {
                let mut g = lifecycle.lock().await;
                let emitted = g.reconcile(vec![intent]).await;
                emitted.iter().any(|e| {
                    matches!(
                        e.outcome,
                        balansir_daemon::driver::lifecycle::DriverOutcome::Failed { .. }
                    )
                })
            };
            refresh_tiers(&lifecycle, metrics, events, tracker).await;
            if failed {
                info!(?id, "driver failed to start");
                IpcMessage::response_error(msg.correlation_id, "Driver failed to start")
            } else {
                info!(?id, "driver started");
                IpcMessage::response_ok(msg.correlation_id)
            }
        }
        MsgType::StopDriver => {
            let Some(id) = driver_id_from_payload(msg) else {
                return IpcMessage::response_error(msg.correlation_id, "Invalid driver id");
            };
            {
                let mut g = lifecycle.lock().await;
                g.reconcile(vec![DriverIntent::stop(id)]).await;
            }
            refresh_tiers(&lifecycle, metrics, events, tracker).await;
            info!(?id, "driver stopped");
            IpcMessage::response_ok(msg.correlation_id)
        }
        // M3.8 CLI / control-plane queries.
        MsgType::GetPlan => {
            let plan = reconciler.build_plan().await;
            let body = postcard::to_allocvec(&plan).unwrap_or_default();
            IpcMessage::response_data(msg.correlation_id, body)
        }
        MsgType::GetExplain => {
            let explanation = reconciler.explain().await;
            IpcMessage::response_data(msg.correlation_id, explanation.into_bytes())
        }
        MsgType::GetDesired => {
            let desired = reconciler.get_desired().await;
            let body = postcard::to_allocvec(&desired).unwrap_or_default();
            IpcMessage::response_data(msg.correlation_id, body)
        }
        MsgType::GetActual => {
            let actual = reconciler.get_actual().await;
            let body = postcard::to_allocvec(&actual).unwrap_or_default();
            IpcMessage::response_data(msg.correlation_id, body)
        }
        MsgType::GetConfigFingerprint => {
            let fp = reconciler.config_fingerprint().await;
            match postcard::to_allocvec(&fp) {
                Ok(body) => IpcMessage::response_data(msg.correlation_id, body),
                Err(_) => IpcMessage::response_error(msg.correlation_id, "encode failed"),
            }
        }
        MsgType::Reload => {
            let Ok(candidate) = postcard::from_bytes::<DesiredState>(&msg.payload) else {
                return IpcMessage::response_error(msg.correlation_id, "invalid reload payload");
            };
            match reconciler
                .reload(candidate, ReconcileReason::ConfigReload)
                .await
            {
                Ok(()) => IpcMessage::response_ok(msg.correlation_id),
                Err(e) => IpcMessage::response_error(msg.correlation_id, &e.to_string()),
            }
        }
        _ => {
            info!("Unknown message type: {:?}", msg.msg_type);
            IpcMessage::response_error(msg.correlation_id, "Unknown message type")
        }
    }
}

/// Safely remove a stale socket file. Refuses symlinks and sockets owned by
/// another UID, so an attacker-controlled file cannot be clobbered or trick us
/// into unlinking an unrelated path.
fn remove_stale_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let md = match std::fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    if !md.file_type().is_socket() {
        return Err(balansir_common::error::Error::Misconfiguration(format!(
            "refusing to remove non-socket at {}",
            path.display()
        )));
    }

    if md.uid() != unsafe { libc::geteuid() } {
        return Err(balansir_common::error::Error::IpcViolation(format!(
            "stale socket at {} owned by different UID",
            path.display()
        )));
    }

    std::fs::remove_file(path)?;
    warn!("Removed stale socket at {}", path.display());
    Ok(())
}
