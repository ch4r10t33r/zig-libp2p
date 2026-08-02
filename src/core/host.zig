//! Canonical libp2p node wiring: bundles [`Swarm`], [`Gossipsub`], [`ReqResp`],
//! and [`ConnectionManager`] into one initializable object (`Host`) with a
//! consistent lifecycle and type-safe convenience helpers.
//!
//! Without `Host`, every embedder writes the same ~250 lines of plumbing to
//! init four subsystems, plumb the shared swarm reference through three of
//! them, register the optional req/resp ↔ connection-manager hook, and drain
//! shutdown events in the right order. This module is that plumbing, in one
//! place, so the next thing embedders write is *their* logic — bootnodes,
//! topic strings, RPC handlers — instead of bring-up boilerplate.
//!
//! Transport (TCP / QUIC listener + dialer + multistream-select + security
//! upgrade) is **still owned by the embedder** because it's where most
//! deployment choices live (cert pinning, ALPN selection, NAT discovery,
//! per-network listen addresses). `Host` exposes the hooks the transport
//! layer calls into — `onConnectionEstablished`, `onConnectionClosed`,
//! `onDialFailure`, `handleGossipRpc` — see `examples/host_quic_node.zig`
//! for the canonical wiring.

const std = @import("std");
const swarm_mod = @import("swarm.zig");
const gossipsub_runtime = @import("../protocols/gossipsub/runtime.zig");
const req_resp_runtime = @import("../protocols/req_resp/runtime.zig");
const connection_manager_mod = @import("connection_manager.zig");
const metrics_mod = @import("../primitives/metrics.zig");
const identity = @import("../primitives/identity.zig");
const peer_events = @import("peer_events.zig");
const protocol_mod = @import("../primitives/protocol.zig");
const multiaddr_mod = @import("multiaddr");
const gs_rpc = @import("../protocols/gossipsub/rpc.zig");
const gs_msg = @import("../protocols/gossipsub/message.zig");
const gs_control = @import("../protocols/gossipsub/control.zig");
const errors_mod = @import("../primitives/errors.zig");
const identify_mod = @import("../protocols/identify/identify.zig");
const identify_ad_mod = @import("identify_advertisement.zig");
const autonat_mod = @import("../protocols/autonat/root.zig");
const peer_protocols_mod = @import("peer_protocols.zig");
const kad_dht_mod = @import("../protocols/kad_dht/root.zig");
const discovery_mod = @import("../protocols/discovery/root.zig");
const wall_time = @import("../primitives/wall_time.zig");

pub const AutonatHostConfig = struct {
    enable: bool = false,
    client: autonat_mod.ClientConfig = .{},
};

pub const MdnsHostConfig = struct {
    enable: bool = false,
    config: discovery_mod.mdns.Config = .{},
};

/// Optional transport hook for outbound AutoNAT probes (#206).
pub const AutonatProbeDispatch = struct {
    ctx: *anyopaque,
    dispatch: *const fn (ctx: *anyopaque, peer: identity.PeerId) void,
};

/// Max [`swarm.Event.identify_push_peer`] events queued per [`Host.runPeriodicTicks`] (#202).
pub const default_max_identify_push_per_tick: u32 = 64;

pub const IdentifyConfig = struct {
    max_push_per_tick: u32 = default_max_identify_push_per_tick,
};

/// Optional transport hook: when set, [`queueIdentifyPush`] invokes this
/// instead of enqueueing [`swarm.Event.identify_push_peer`] (used by
/// [`transport.quic_runtime.QuicRuntime`]).
pub const IdentifyPushDispatch = struct {
    ctx: *anyopaque,
    dispatch: *const fn (ctx: *anyopaque, peer: identity.PeerId) void,
};

/// Union of every typed error the gossipsub runtime can surface, in one alias
/// so Host method signatures stay legible.
pub const GossipsubError = gs_rpc.Error || gs_msg.Error || gs_control.Error ||
    errors_mod.GossipsubError || std.mem.Allocator.Error;

pub const SwarmBootConfig = struct {
    event_capacity: usize = swarm_mod.default_event_capacity,
    command_ring_capacity: usize = 0,
    /// Optional real-transport interception hook (#TBD). See
    /// [`swarm_mod.CommandDispatchHook`].
    command_dispatch: ?swarm_mod.CommandDispatchHook = null,
    /// MUST default to a non-blocking policy: the QUIC drive thread produces
    /// these events, and `.block` makes `queueEvent` wait for the application
    /// consumer (e.g. the consensus/signature-verification thread draining via
    /// `nextEvent`). When that consumer falls behind under load, a `.block`
    /// producer freezes the ENTIRE drive loop — it stops sending ACKs to all
    /// peers, who then declare the node lost after 60s (observed live: deaths
    /// with acked=MBs, lost=0, healthy cwnd — a pure stall, not congestion).
    /// `.drop_oldest` keeps the freshest events and never stalls the reactor;
    /// rust-libp2p likewise never blocks its network task on the app consumer.
    event_queue_policy: swarm_mod.EventQueuePolicy = .drop_oldest,
    hook_deadline_ms: u32 = swarm_mod.default_hook_deadline_ms,
};

pub const HostConfig = struct {
    allocator: std.mem.Allocator,
    /// Required: the node's libp2p PeerId. Used by gossipsub for mesh
    /// membership decisions and by swarm metrics labels.
    local_peer: identity.PeerId,
    /// Optional shared metrics registry. When set, both `Swarm` and
    /// `Gossipsub` write into it; embedders typically expose this via a
    /// `/metrics` HTTP endpoint.
    metrics: ?*metrics_mod.Metrics = null,
    /// Swarm queue sizing. Defaults match `swarm.default_event_capacity`.
    swarm: SwarmBootConfig = .{},
    /// Gossipsub knobs. `local_peer_id` is auto-populated from `local_peer`
    /// if left at the default sentinel.
    gossipsub: gossipsub_runtime.GossipsubConfig,
    /// Req/resp knobs (timeouts, idle window).
    req_resp: req_resp_runtime.ReqRespConfig = .{},
    /// Connection-manager trim policy. Defaults to "unlimited" (`null` knobs).
    connection_limits: connection_manager_mod.ConnectionLimits = .{},
    /// Peers registered at init as trim-exempt (bootnodes, direct peers) ([#210](https://github.com/blockblaz/zig-libp2p/issues/210)).
    protected_peers: []const identity.PeerId = &.{},
    /// Identify Push auto-trigger batching (#202).
    identify: IdentifyConfig = .{},
    /// AutoNAT vote aggregation + active probing (#206).
    autonat: AutonatHostConfig = .{},
    /// mDNS LAN peer discovery (#207).
    mdns: MdnsHostConfig = .{},
};

pub const InitError = error{
    SwarmInitFailed,
    GossipsubInitFailed,
    ConnectionManagerInitFailed,
} || std.mem.Allocator.Error;

/// Canonical libp2p node bundle. Owns its component subsystems; on
/// [`destroy`] tears them down in the order required to drain pending
/// outbound RPCs and gossip queues before the swarm ring vanishes.
pub const Host = struct {
    allocator: std.mem.Allocator,
    /// Swarm command + event queue. Owned (heap).
    swarm: *swarm_mod.Swarm,
    /// Gossipsub mesh runtime. Owned (heap, via `Gossipsub.init`).
    gossipsub: *gossipsub_runtime.Gossipsub,
    /// Req/resp runtime. Owned (heap, via `ReqResp.create`).
    req_resp: *req_resp_runtime.ReqResp,
    /// Known-peer dial scheduling + trim policy. Owned (heap; `ConnectionManager`
    /// is small but we keep it on the heap so callers can hand `&host.connection_manager`
    /// to the transport layer without worrying about Host moves).
    connection_manager: *connection_manager_mod.ConnectionManager,
    /// Local Identify advertisement inputs (listen addrs, protocols, SPR).
    identify_ad: identify_ad_mod.Advertisement,
    identify_addr_scratch: std.ArrayList([]const u8) = .empty,
    identify_proto_scratch: std.ArrayList([]const u8) = .empty,
    identify_max_push_per_tick: u32,
    identify_push_dispatch: ?IdentifyPushDispatch = null,
    autonat_client: ?autonat_mod.Client = null,
    peer_protocols: peer_protocols_mod.Store,
    autonat_probe_dispatch: ?AutonatProbeDispatch = null,
    kad_dht_client: ?*kad_dht_mod.Client = null,
    mdns_service: ?*discovery_mod.mdns.Service = null,
    autonat_addr_scratch: std.ArrayList([]const u8) = .empty,
    /// External addresses other peers reported observing us from (identify
    /// `observed_addr`). Used as AutoNAT probe candidates — listen addrs are
    /// `/ip4/0.0.0.0/...` wildcards and cannot be dialed back (#206).
    observed_addrs: std.StringHashMap(void),
    autonat_candidate_scratch: std.ArrayList([]const u8) = .empty,
    last_autonat_node_status: autonat_mod.NatStatus = .unknown,

    pub fn create(cfg: HostConfig) InitError!*Host {
        const allocator = cfg.allocator;

        const self = try allocator.create(Host);
        errdefer allocator.destroy(self);

        const swarm = try allocator.create(swarm_mod.Swarm);
        errdefer allocator.destroy(swarm);
        swarm.* = swarm_mod.Swarm.initWithConfig(allocator, .{
            .event_capacity = cfg.swarm.event_capacity,
            .local_peer = cfg.local_peer,
            .command_ring_capacity = cfg.swarm.command_ring_capacity,
            .metrics = cfg.metrics,
            .command_dispatch = cfg.swarm.command_dispatch,
            .event_queue_policy = cfg.swarm.event_queue_policy,
            .hook_deadline_ms = cfg.swarm.hook_deadline_ms,
        }) catch return error.SwarmInitFailed;
        errdefer swarm.deinit();

        // Auto-bind `gossipsub.local_peer_id` if the embedder left it as the
        // sentinel `.local_peer_id = .{}` (matching identity.PeerId's zero
        // value would be ambiguous, so we always overwrite — embedders that
        // *really* want a different PeerId on gossipsub vs. swarm should
        // construct the components manually rather than via Host).
        var gs_cfg = cfg.gossipsub;
        gs_cfg.local_peer_id = cfg.local_peer;
        if (gs_cfg.metrics == null) gs_cfg.metrics = cfg.metrics;
        const gs = gossipsub_runtime.Gossipsub.init(allocator, gs_cfg) catch return error.GossipsubInitFailed;
        errdefer gs.deinit();

        const rr = try req_resp_runtime.ReqResp.create(allocator, swarm, cfg.req_resp);
        errdefer rr.destroy();

        const cm = try allocator.create(connection_manager_mod.ConnectionManager);
        errdefer allocator.destroy(cm);
        cm.* = connection_manager_mod.ConnectionManager.init(allocator, swarm);
        cm.setLimits(cfg.connection_limits);
        cm.setReqResp(rr);
        for (cfg.protected_peers) |peer| {
            try cm.protect(peer);
        }

        var autonat_client: ?autonat_mod.Client = null;
        if (cfg.autonat.enable) {
            autonat_client = autonat_mod.Client.init(allocator, cfg.autonat.client);
        }

        var mdns_service: ?*discovery_mod.mdns.Service = null;
        if (cfg.mdns.enable) {
            const m = try allocator.create(discovery_mod.mdns.Service);
            errdefer allocator.destroy(m);
            m.* = discovery_mod.mdns.Service.init(allocator, cfg.local_peer, cfg.mdns.config) catch return error.SwarmInitFailed;
            mdns_service = m;
        }

        self.* = .{
            .allocator = allocator,
            .swarm = swarm,
            .gossipsub = gs,
            .req_resp = rr,
            .connection_manager = cm,
            .identify_ad = identify_ad_mod.Advertisement.init(allocator),
            .identify_max_push_per_tick = cfg.identify.max_push_per_tick,
            .autonat_client = autonat_client,
            .peer_protocols = peer_protocols_mod.Store.init(allocator),
            .observed_addrs = std.StringHashMap(void).init(allocator),
            .mdns_service = mdns_service,
        };
        return self;
    }

    pub fn destroy(self: *Host) void {
        // Order matters: shut down command flow first so no new submits land
        // mid-deinit, then drain in dependency order (req/resp → conn_mgr →
        // gossipsub → swarm). The swarm's own deinit drains its ring.
        self.swarm.shutdown();
        self.req_resp.destroy();
        self.connection_manager.deinit();
        self.allocator.destroy(self.connection_manager);
        self.gossipsub.deinit();
        self.identify_ad.deinit();
        self.identify_addr_scratch.deinit(self.allocator);
        self.identify_proto_scratch.deinit(self.allocator);
        if (self.autonat_client) |*c| c.deinit();
        if (self.mdns_service) |m| {
            m.deinit();
            self.allocator.destroy(m);
        }
        self.peer_protocols.deinit();
        self.autonat_addr_scratch.deinit(self.allocator);
        var oit = self.observed_addrs.keyIterator();
        while (oit.next()) |k| self.allocator.free(k.*);
        self.observed_addrs.deinit();
        self.autonat_candidate_scratch.deinit(self.allocator);
        self.swarm.deinit();
        self.allocator.destroy(self.swarm);
        self.allocator.destroy(self);
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    /// Spawns the swarm background worker. Idempotent.
    pub fn startBackground(self: *Host) std.Thread.SpawnError!void {
        try self.swarm.startBackground();
    }

    /// Blocks until the worker has entered its loop (or `tick` has been called
    /// in single-threaded mode). See [`Swarm.waitUntilReady`].
    pub fn waitUntilReady(self: *Host, timeout_ms: u32) bool {
        return self.swarm.waitUntilReady(timeout_ms);
    }

    pub fn isReady(self: *Host) bool {
        return self.swarm.isReady();
    }

    /// Signals shutdown without waiting. Pair with `nextEvent` until
    /// `Event.swarm_closed` arrives, then `destroy`.
    pub fn shutdown(self: *Host) void {
        self.swarm.shutdown();
    }

    /// Single-threaded driver step: drains up to `budget` commands and runs
    /// periodic ticks (gossipsub heartbeat, req/resp timeouts, conn-mgr dial
    /// scheduling). Background-mode embedders don't call this; the worker
    /// handles command dispatch and the embedder calls
    /// [`runPeriodicTicks`] from its own clock instead.
    pub fn tick(self: *Host, command_budget: u32, now_ms: i64) (GossipsubError || req_resp_runtime.Error || std.mem.Allocator.Error || swarm_mod.SubmitError || discovery_mod.mdns.Error)!void {
        _ = self.swarm.tick(command_budget);
        try self.runPeriodicTicks(now_ms);
    }

    /// Runs the periodic per-subsystem ticks: gossipsub heartbeat, req/resp
    /// timeout sweep, connection-manager dial scheduling. Call once per
    /// heartbeat interval (default 700ms) from your reactor.
    pub fn runPeriodicTicks(self: *Host, now_ms: i64) (GossipsubError || req_resp_runtime.Error || std.mem.Allocator.Error || swarm_mod.SubmitError || discovery_mod.mdns.Error)!void {
        self.gossipsub.setClockMs(now_ms);
        try self.gossipsub.heartbeat();
        try self.req_resp.tick(now_ms);
        try self.connection_manager.tick(now_ms);
        try self.flushIdentifyPushIfDirty();
        try self.tickAutonat(now_ms);
        try self.tickKadDht(now_ms);
        try self.tickMdns(now_ms);
    }

    fn tickMdns(self: *Host, now_ms: i64) (std.mem.Allocator.Error || swarm_mod.SubmitError || discovery_mod.mdns.Error)!void {
        const m = self.mdns_service orelse return;
        try m.setListenAddrs(self.identify_ad.listen_addrs.items);
        const discoveries = try m.tick(now_ms);
        defer m.freeDiscoveries(discoveries);
        for (discoveries) |d| {
            for (d.addrs) |addr| {
                var ma = multiaddr_mod.Multiaddr.fromString(self.allocator, addr) catch continue;
                defer ma.deinit();
                self.registerKnownPeer(&ma, d.peer) catch {};
            }
            const owned_addrs = try self.allocator.alloc([]const u8, d.addrs.len);
            errdefer {
                for (owned_addrs) |a| self.allocator.free(a);
                self.allocator.free(owned_addrs);
            }
            for (d.addrs, 0..) |addr, i| {
                owned_addrs[i] = try self.allocator.dupe(u8, addr);
            }
            try self.swarm.queueEvent(.{ .peer_discovered = .{
                .peer = d.peer,
                .addrs = owned_addrs,
                .source = .mdns,
            } });
        }
    }

    fn tickKadDht(self: *Host, now_ms: i64) std.mem.Allocator.Error!void {
        const kad = self.kad_dht_client orelse return;
        const addrs = self.identify_ad.listen_addrs.items;
        if (addrs.len == 0) return;
        kad.republishProviders(addrs, now_ms) catch {};
    }

    fn tickAutonat(self: *Host, now_ms: i64) std.mem.Allocator.Error!void {
        const client = blk: {
            if (self.autonat_client) |*c| break :blk c;
            return;
        };

        const candidates = try self.buildAutonatCandidates();
        // No concrete public candidate addr → reachability is undeterminable;
        // skip probing rather than asking servers to dial wildcards (#206).
        if (candidates.len == 0) return;

        var connected: std.ArrayList(identity.PeerId) = .empty;
        defer connected.deinit(self.allocator);
        try self.connection_manager.collectConnectedPeers(&connected);

        var servers: std.ArrayList(identity.PeerId) = .empty;
        defer servers.deinit(self.allocator);
        try self.peer_protocols.collectAutonatServers(connected.items, &servers);

        client.scheduleActiveProbes(now_ms, self.swarm.local_peer, servers.items, candidates) catch {};

        for (servers.items) |peer| {
            if (!client.hasPendingProbe(peer)) continue;
            try self.queueAutonatProbe(peer);
        }

        const changes = client.takeReachabilityChanges();
        defer client.freeReachabilityChanges(changes);
        for (changes) |ch| {
            try self.swarm.queueEvent(.{ .reachability_changed = .{
                .addr = try self.allocator.dupe(u8, ch.addr),
                .status = ch.status,
            } });
        }

        const node_status = client.natStatus();
        if (node_status != self.last_autonat_node_status) {
            self.last_autonat_node_status = node_status;
            if (self.kad_dht_client) |kad| {
                kad.setMode(kad_dht_mod.mode.fromNatStatus(node_status));
            }
        }
    }

    fn queueAutonatProbe(self: *Host, peer: identity.PeerId) std.mem.Allocator.Error!void {
        if (self.autonat_probe_dispatch) |d| {
            d.dispatch(d.ctx, peer);
            return;
        }
        try self.swarm.queueEvent(.{ .autonat_probe_peer = peer });
    }

    pub fn setAutonatProbeDispatch(self: *Host, dispatch: ?AutonatProbeDispatch) void {
        self.autonat_probe_dispatch = dispatch;
    }

    pub fn setKadDhtClient(self: *Host, client: ?*kad_dht_mod.Client) void {
        self.kad_dht_client = client;
    }

    pub fn recordPeerProtocols(self: *Host, peer: identity.PeerId, protocols: []const []const u8) std.mem.Allocator.Error!void {
        try self.peer_protocols.setProtocols(peer, protocols);
    }

    /// Cap on stored observed external addresses (#206). Bounds memory against
    /// peers reporting many distinct `observed_addr` values.
    const max_observed_addrs: usize = 16;

    /// Record an external address a peer observed us from (identify
    /// `observed_addr`). Deduped and bounded; used as an AutoNAT probe
    /// candidate when it is a concrete public address (#206).
    pub fn recordObservedAddr(self: *Host, addr: []const u8) std.mem.Allocator.Error!void {
        if (self.autonat_client == null) return;
        if (!autonat_mod.policy.isDialableCandidate(self.allocator, addr)) return;
        if (self.observed_addrs.contains(addr)) return;
        if (self.observed_addrs.count() >= max_observed_addrs) return;
        const owned = try self.allocator.dupe(u8, addr);
        errdefer self.allocator.free(owned);
        try self.observed_addrs.put(owned, {});
    }

    /// Build the AutoNAT probe-candidate list into `autonat_candidate_scratch`:
    /// observed external addrs plus any concrete/public operator announce addrs,
    /// deduped. Wildcard/private addrs are filtered out (#206). Returned slices
    /// borrow scratch storage valid until the next call.
    fn buildAutonatCandidates(self: *Host) std.mem.Allocator.Error![]const []const u8 {
        self.autonat_candidate_scratch.clearRetainingCapacity();
        var oit = self.observed_addrs.keyIterator();
        while (oit.next()) |k| {
            try self.autonat_candidate_scratch.append(self.allocator, k.*);
        }
        self.autonat_addr_scratch.clearRetainingCapacity();
        const params = self.identify_ad.replyParamsInto(
            &self.autonat_addr_scratch,
            &self.identify_proto_scratch,
        );
        for (params.listen_addrs) |addr| {
            if (!autonat_mod.policy.isDialableCandidate(self.allocator, addr)) continue;
            var dup = false;
            for (self.autonat_candidate_scratch.items) |c| {
                if (std.mem.eql(u8, c, addr)) {
                    dup = true;
                    break;
                }
            }
            if (!dup) try self.autonat_candidate_scratch.append(self.allocator, addr);
        }
        return self.autonat_candidate_scratch.items;
    }

    pub fn takeAutonatProbeForPeer(self: *Host, peer: identity.PeerId) ?autonat_mod.OutboundProbe {
        if (self.autonat_client) |*c| return c.takePendingProbe(peer);
        return null;
    }

    pub fn freeAutonatProbeMessage(self: *Host, msg: []const u8) void {
        if (self.autonat_client) |*c| c.freeProbeMessage(msg);
    }

    pub fn handleAutonatV1Response(self: *Host, resp: autonat_mod.wire.V1DialResponse) std.mem.Allocator.Error!void {
        const client = blk: {
            if (self.autonat_client) |*c| break :blk c;
            return;
        };
        const candidates = try self.buildAutonatCandidates();
        try client.handleV1DialResponse(resp, candidates);
        const changes = client.takeReachabilityChanges();
        defer client.freeReachabilityChanges(changes);
        for (changes) |ch| {
            try self.swarm.queueEvent(.{ .reachability_changed = .{
                .addr = try self.allocator.dupe(u8, ch.addr),
                .status = ch.status,
            } });
        }
        const node_status = client.natStatus();
        if (node_status != self.last_autonat_node_status) {
            self.last_autonat_node_status = node_status;
            if (self.kad_dht_client) |kad| {
                kad.setMode(kad_dht_mod.mode.fromNatStatus(node_status));
            }
        }
    }

    fn flushIdentifyPushIfDirty(self: *Host) std.mem.Allocator.Error!void {
        if (!self.identify_ad.takeDirty()) return;
        var peers: std.ArrayList(identity.PeerId) = .empty;
        defer peers.deinit(self.allocator);
        try self.connection_manager.collectConnectedPeers(&peers);
        const cap = @min(peers.items.len, @as(usize, self.identify_max_push_per_tick));
        for (peers.items[0..cap]) |peer| {
            try self.queueIdentifyPush(peer);
        }
        if (peers.items.len > cap) self.identify_ad.markDirty();
    }

    fn queueIdentifyPush(self: *Host, peer: identity.PeerId) std.mem.Allocator.Error!void {
        if (self.identify_push_dispatch) |d| {
            d.dispatch(d.ctx, peer);
            return;
        }
        try self.swarm.queueEvent(.{ .identify_push_peer = peer });
    }

    /// Register a transport that opens `/ipfs/id/push/1.0.0` directly (QUIC
    /// runtime). Cleared automatically when the transport is destroyed.
    pub fn setIdentifyPushDispatch(self: *Host, dispatch: ?IdentifyPushDispatch) void {
        self.identify_push_dispatch = dispatch;
    }

    // ── Identify (#202) ───────────────────────────────────────────────────

    pub fn setListenAddrs(self: *Host, addrs: []const []const u8) std.mem.Allocator.Error!void {
        try self.identify_ad.setListenAddrs(addrs);
    }

    pub fn addListenAddr(self: *Host, addr: []const u8) std.mem.Allocator.Error!void {
        try self.identify_ad.addListenAddr(addr);
    }

    pub fn removeListenAddr(self: *Host, addr: []const u8) void {
        self.identify_ad.removeListenAddr(addr);
    }

    pub fn addProtocol(self: *Host, proto: []const u8) std.mem.Allocator.Error!void {
        try self.identify_ad.addProtocol(proto);
    }

    pub fn removeProtocol(self: *Host, proto: []const u8) void {
        self.identify_ad.removeProtocol(proto);
    }

    pub fn setIdentifyPublicKey(self: *Host, key: ?[]const u8) std.mem.Allocator.Error!void {
        try self.identify_ad.setPublicKey(key);
    }

    pub fn setSignedPeerRecord(self: *Host, spr: ?[]const u8, seq: u64) std.mem.Allocator.Error!void {
        try self.identify_ad.setSignedPeerRecord(spr, seq);
    }

    pub fn markIdentifyDirty(self: *Host) void {
        self.identify_ad.markDirty();
    }

    /// Wire payload for [`identify_mod.Identify.sendPush`] on
    /// [`swarm_mod.Event.identify_push_peer`] streams.
    pub fn identifyReplyParams(self: *Host) identify_mod.ReplyParams {
        return self.identify_ad.replyParamsInto(
            &self.identify_addr_scratch,
            &self.identify_proto_scratch,
        );
    }

    /// Queue one Identify Push for `peer` when a connection is active (#202).
    pub fn sendIdentifyPush(self: *Host, peer: identity.PeerId) std.mem.Allocator.Error!void {
        if (!self.connection_manager.hasActiveConnection(peer)) return;
        try self.queueIdentifyPush(peer);
    }

    // ── Pub/sub ────────────────────────────────────────────────────────────

    pub fn subscribe(self: *Host, topic: []const u8) (GossipsubError || swarm_mod.SubmitError)!void {
        try self.swarm.submit(.{ .subscribe = .{ .topic = topic } });
        _ = try self.gossipsub.subscribe(topic);
    }

    pub fn publish(self: *Host, topic: []const u8, data: []const u8) (GossipsubError || swarm_mod.SubmitError)!void {
        try self.swarm.submit(.{ .publish = .{ .topic = topic, .payload = data } });
        try self.gossipsub.publish(topic, data);
    }

    pub fn addDirectPeer(self: *Host, peer: identity.PeerId) std.mem.Allocator.Error!void {
        try self.gossipsub.addDirectPeer(peer);
    }

    pub fn removeDirectPeer(self: *Host, peer: identity.PeerId) void {
        self.gossipsub.removeDirectPeer(peer);
    }

    /// Receive an inbound gossipsub RPC frame from the transport layer. Call
    /// from the embedder's stream-dispatch path after multistream-select
    /// negotiates `/meshsub/1.1.0` and the snappy-framed frame is reassembled.
    pub fn handleGossipRpc(self: *Host, sender: identity.PeerId, frame: []const u8) GossipsubError!void {
        try self.gossipsub.handleInboundRpc(sender, frame);
    }

    // ── Req/resp ───────────────────────────────────────────────────────────

    pub fn sendRequest(
        self: *Host,
        peer: identity.PeerId,
        proto: protocol_mod.LeanSupportedProtocol,
        payload: []const u8,
        timeout_ms: u32,
    ) (req_resp_runtime.Error || swarm_mod.SubmitError || std.mem.Allocator.Error)!u64 {
        // Per-call `timeout_ms` is advisory; the effective request timeout is
        // governed by `cfg.request_timeout_ms` inside the req/resp runtime.
        _ = timeout_ms;
        // `req_resp.sendRequest`'s last parameter is the CURRENT wall-clock time
        // (`now_ms`), from which it derives the request deadline
        // (`now_ms + cfg.request_timeout_ms`). Passing `timeout_ms` here set the
        // deadline to ~`timeout_ms` ms after the Unix epoch — decades in the past
        // — so the very next `req_resp.tick(now_ms)` sweep (driven from the same
        // wall clock) expired the request instantly with `StreamTimedOut`. That
        // raced the response round-trip: fast local round-trips won ~90% of the
        // time, but a slower live round-trip (e.g. a rust peer opening a
        // server-initiated status stream back to us) lost the race almost every
        // time, so we appeared to fail the request in a few ms and the peer
        // closed the connection. Pass the real clock; the per-call `timeout_ms`
        // is advisory only (the effective timeout is `cfg.request_timeout_ms`).
        return self.req_resp.sendRequest(peer, proto, payload, wall_time.milliTimestamp());
    }

    pub fn registerInboundReqRespChannel(
        self: *Host,
        peer: identity.PeerId,
        proto: protocol_mod.LeanSupportedProtocol,
        request_id: u64,
        now_ms: i64,
    ) std.mem.Allocator.Error!u64 {
        return self.req_resp.registerInboundChannel(peer, proto, request_id, now_ms);
    }

    pub fn sendResponseChunk(self: *Host, channel_id: u64, payload: []const u8, now_ms: i64) (req_resp_runtime.Error || swarm_mod.SubmitError)!void {
        return self.req_resp.sendResponseChunk(channel_id, payload, now_ms);
    }

    pub fn finishResponseStream(self: *Host, channel_id: u64) (req_resp_runtime.Error || swarm_mod.SubmitError)!void {
        return self.req_resp.finishResponseStream(channel_id);
    }

    pub fn sendErrorResponse(self: *Host, channel_id: u64, message: []const u8) (req_resp_runtime.Error || swarm_mod.SubmitError)!void {
        return self.req_resp.sendErrorResponse(channel_id, message);
    }

    pub fn sendErrorResponseWithCode(self: *Host, channel_id: u64, response_code: u8, message: []const u8) (req_resp_runtime.Error || swarm_mod.SubmitError)!void {
        return self.req_resp.sendErrorResponseWithCode(channel_id, response_code, message);
    }

    // ── Known peers / dialing ─────────────────────────────────────────────

    pub fn registerKnownPeer(
        self: *Host,
        ma: *const multiaddr_mod.Multiaddr,
        peer_override: ?identity.PeerId,
    ) connection_manager_mod.ConnectionManager.RegisterError!void {
        try self.connection_manager.registerKnownPeer(ma, peer_override);
    }

    pub fn knownPeerStatus(self: *const Host, peer: identity.PeerId) ?connection_manager_mod.KnownPeerDialStatus {
        return self.connection_manager.knownPeerStatus(peer);
    }

    /// Exempt `peer` from connection trim recommendations ([#210](https://github.com/blockblaz/zig-libp2p/issues/210)).
    pub fn protectPeer(self: *Host, peer: identity.PeerId) !void {
        try self.connection_manager.protect(peer);
    }

    /// Clear trim protection for `peer` ([#210](https://github.com/blockblaz/zig-libp2p/issues/210)).
    pub fn unprotectPeer(self: *Host, peer: identity.PeerId) void {
        self.connection_manager.unprotect(peer);
    }

    // ── Drain ──────────────────────────────────────────────────────────────

    pub fn nextEvent(self: *Host, timeout_ms: u32) swarm_mod.NextEventError!swarm_mod.Event {
        return self.swarm.nextEvent(timeout_ms);
    }

    // ── Transport hooks ───────────────────────────────────────────────────

    pub fn onConnectionEstablished(
        self: *Host,
        conn_id: connection_manager_mod.ConnectionId,
        peer: identity.PeerId,
        direction: peer_events.Direction,
        opts: connection_manager_mod.ConnectionEstablishedOptions,
    ) (std.mem.Allocator.Error || swarm_mod.SubmitError)!void {
        try self.connection_manager.onConnectionEstablished(conn_id, peer, direction, opts);
        self.gossipsub.onPeerConnected(peer);
    }

    pub fn onConnectionClosed(
        self: *Host,
        now_ms: i64,
        conn_id: connection_manager_mod.ConnectionId,
        peer: identity.PeerId,
        reason: peer_events.DisconnectReason,
    ) (std.mem.Allocator.Error || swarm_mod.SubmitError)!void {
        const fully_disconnected = try self.connection_manager.onConnectionClosed(now_ms, conn_id, reason);
        // Only tear down PEER-level state (keyed by PeerId, not conn_id) when the
        // peer's LAST leg closed. With sharding a peer commonly holds two legs on
        // different shards; a single leg flap must NOT wipe gossipsub
        // `remote_interest` / mesh membership, else sparse subnet meshes bleed a
        // member on every flap and the heartbeat can never re-graft them (the
        // candidate pool empties → coverage decays below quorum → finality stalls).
        if (fully_disconnected) {
            self.teardownPeerState(peer);
        }
    }

    /// Peer-level teardown shared by the LAST-leg close path above and the
    /// #299 reconciliation sweep (which repairs `peer_active` entries stranded
    /// with zero backing connections and must then run the same teardown a
    /// delivered last-leg close would have run).
    pub fn teardownPeerState(self: *Host, peer: identity.PeerId) void {
        self.gossipsub.onPeerDisconnected(peer);
        self.peer_protocols.removePeer(peer);
        if (self.kad_dht_client) |kad| {
            var peer_b58: [128]u8 = undefined;
            const peer_str = peer.toBase58(&peer_b58) catch return;
            kad.onPeerDisconnected(peer_str);
        }
    }

    pub fn onDialFailure(
        self: *Host,
        now_ms: i64,
        conn_id: connection_manager_mod.ConnectionId,
        peer: ?identity.PeerId,
        direction: peer_events.Direction,
        result: peer_events.ConnectionFailureResult,
    ) (std.mem.Allocator.Error || swarm_mod.SubmitError)!void {
        try self.connection_manager.onDialFailure(now_ms, conn_id, peer, direction, result);
    }
};

// ── Tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Host.create / destroy round trip" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();

    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    try testing.expect(host.gossipsub.cfg.local_peer_id.eql(&me));
}

test "Host autonat probe candidates come from observed addrs, filtered" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
        .autonat = .{ .enable = true },
    });
    defer host.destroy();

    // Wildcard and private observed addrs are rejected; the public one becomes
    // the sole (deduped) probe candidate — listen wildcards can't be dialed back.
    try host.recordObservedAddr("/ip4/0.0.0.0/udp/4001/quic-v1");
    try host.recordObservedAddr("/ip4/10.0.0.5/udp/4001/quic-v1");
    try host.recordObservedAddr("/ip4/203.0.113.9/udp/4001/quic-v1");
    try host.recordObservedAddr("/ip4/203.0.113.9/udp/4001/quic-v1");

    const candidates = try host.buildAutonatCandidates();
    try testing.expectEqual(@as(usize, 1), candidates.len);
    try testing.expectEqualStrings("/ip4/203.0.113.9/udp/4001/quic-v1", candidates[0]);
}

test "Host.startBackground + waitUntilReady chains to swarm" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    try testing.expect(!host.isReady());
    try host.startBackground();
    try testing.expect(host.waitUntilReady(5_000));
    try testing.expect(host.isReady());
}

test "Host.subscribe forwards to gossipsub" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    try host.subscribe("blocks");
    try testing.expect(host.gossipsub.subs.contains("blocks"));

    // The subscribe broadcast was also pushed into the swarm queue; drain it
    // so deinit doesn't complain about leaked OwnedCommand.
    host.swarm.tick(8);
}

test "Host req/resp wrapper methods compile + route to runtime" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    // Regression for the v0.1.0 type-annotation bug: `Host.sendResponseChunk`
    // / `finishResponseStream` / `sendErrorResponse` named `ReqResp.Error`
    // where the type actually lives at module scope as `req_resp_runtime.Error`.
    // Lazy compilation hid this in v0.1.0 because no test referenced the
    // wrappers; this test does, so the signatures stay correct going forward.
    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    // No inbound channel registered → both methods return `UnknownInboundChannel`.
    // Routing through the wrappers exercises the type annotations.
    try testing.expectError(error.UnknownInboundChannel, host.sendResponseChunk(999, "x", 0));
    try testing.expectError(error.UnknownInboundChannel, host.finishResponseStream(999));
    try testing.expectError(error.UnknownInboundChannel, host.sendErrorResponse(999, "boom"));

    // tick / runPeriodicTicks reference the same union; calling them is the
    // straightforward way to anchor the annotation against future refactors.
    try host.runPeriodicTicks(0);
    try host.tick(8, 0);
}

test "Host transport hooks update both connection_manager and gossipsub" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    const peer = try identity.PeerId.random();
    try host.onConnectionEstablished(1, peer, .outbound, .{});
    try testing.expect(host.gossipsub.connected.contains(peer));

    // Drain the peer_connected event queued by ConnectionManager.
    try host.startBackground();
    _ = host.waitUntilReady(5_000);
    var ev = try host.nextEvent(1_000);
    defer ev.deinit(a);
    try testing.expectEqual(@as(std.meta.Tag(swarm_mod.Event), .peer_connected), std.meta.activeTag(ev));

    _ = try host.onConnectionClosed(1_000, 1, peer, .remote_close);
    try testing.expect(!host.gossipsub.connected.contains(peer));
}

test "Host dirty identify advert queues identify_push_peer for connected peers" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
        .identify = .{ .max_push_per_tick = 8 },
    });
    defer host.destroy();

    const peer_a = try identity.PeerId.random();
    const peer_b = try identity.PeerId.random();
    try host.onConnectionEstablished(1, peer_a, .outbound, .{});
    try host.onConnectionEstablished(2, peer_b, .inbound, .{});

    // Drain peer_connected events from connection manager.
    try host.startBackground();
    _ = host.waitUntilReady(5_000);
    while (true) {
        var ev = host.nextEvent(100) catch break;
        defer ev.deinit(a);
        if (std.meta.activeTag(ev) == .peer_connected) continue;
        break;
    }

    try host.addListenAddr("/ip4/127.0.0.1/udp/4001/quic-v1");
    try host.runPeriodicTicks(0);

    var saw_a = false;
    var saw_b = false;
    while (true) {
        var ev = host.nextEvent(100) catch break;
        defer ev.deinit(a);
        switch (ev) {
            .identify_push_peer => |p| {
                if (p.eql(&peer_a)) saw_a = true;
                if (p.eql(&peer_b)) saw_b = true;
            },
            .swarm_closed => break,
            else => {},
        }
        if (saw_a and saw_b) break;
    }
    try testing.expect(saw_a);
    try testing.expect(saw_b);
}

test "Host.sendIdentifyPush skips disconnected peer" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    const peer = try identity.PeerId.random();
    try host.sendIdentifyPush(peer);
    try host.startBackground();
    _ = host.waitUntilReady(5_000);
    const ev = host.nextEvent(50);
    try testing.expect(ev == error.Timeout);
}

test "Host identify push dispatch bypasses swarm queue" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    var saw_push = false;
    const ctx = &saw_push;
    const on_push = struct {
        fn cb(ctx_ptr: *anyopaque, _: identity.PeerId) void {
            const flag: *bool = @ptrCast(@alignCast(ctx_ptr));
            flag.* = true;
        }
    }.cb;
    host.setIdentifyPushDispatch(.{ .ctx = ctx, .dispatch = on_push });

    const peer = try identity.PeerId.random();
    try host.onConnectionEstablished(1, peer, .outbound, .{});
    try host.sendIdentifyPush(peer);
    try testing.expect(saw_push);

    try host.startBackground();
    _ = host.waitUntilReady(5_000);
    while (host.nextEvent(100) catch null) |evt| {
        var e = evt;
        defer e.deinit(a);
        try testing.expect(std.meta.activeTag(e) != .identify_push_peer);
        if (std.meta.activeTag(e) == .peer_connected) continue;
        break;
    }
}

test "Host onConnectionClosed evicts kad routing-table peer" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    const KadCtx = struct {
        fn noop(_: ?*anyopaque, _: []const u8, _: kad_dht_mod.MessageView, response_out: *kad_dht_mod.MessageOwned) !void {
            response_out.* = .{ .msg_type = .find_node };
        }
    };

    var peer_b58_buf: [128]u8 = undefined;
    const me_b58 = try me.toBase58(&peer_b58_buf);
    var kad = try kad_dht_mod.Client.init(a, me_b58, .{}, KadCtx.noop);
    defer kad.deinit();
    host.setKadDhtClient(&kad);

    const remote = try identity.PeerId.random();
    var remote_b58_buf: [128]u8 = undefined;
    const remote_b58 = try remote.toBase58(&remote_b58_buf);
    const addr = [_][]const u8{"/ip4/127.0.0.1/udp/4001/quic-v1"};
    _ = try kad.routingTable().update(remote_b58, &addr, .server, 0);
    try testing.expect(kad.routingTable().contains(remote_b58));

    try host.onConnectionEstablished(1, remote, .outbound, .{});
    _ = try host.onConnectionClosed(1_000, 1, remote, .remote_close);
    try testing.expect(!kad.routingTable().contains(remote_b58));
}

test "Host runPeriodicTicks republishes kad providers" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
    });
    defer host.destroy();

    const KadCtx = struct {
        calls: usize = 0,
        fn query(ctx: ?*anyopaque, _: []const u8, request: kad_dht_mod.MessageView, response_out: *kad_dht_mod.MessageOwned) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (request.msg_type == .add_provider) self.calls += 1;
            response_out.* = .{ .msg_type = .add_provider };
        }
    };
    var kad_ctx: KadCtx = .{};

    var me_b58_buf: [128]u8 = undefined;
    const me_b58 = try me.toBase58(&me_b58_buf);
    var kad = try kad_dht_mod.Client.init(a, me_b58, .{
        .records = .{ .provider_ttl_ms = 10_000, .provider_republish_ms = 100 },
    }, KadCtx.query);
    defer kad.deinit();
    kad.setQueryContext(&kad_ctx);
    host.setKadDhtClient(&kad);

    const addr = [_][]const u8{"/ip4/203.0.113.9/udp/4001/quic-v1"};
    _ = try kad.routingTable().update("peer-b", &addr, .server, 0);
    try host.addListenAddr(addr[0]);
    try kad.addLocalProvider("content-key", me_b58, &addr, 0);

    try host.runPeriodicTicks(0);
    try testing.expectEqual(@as(usize, 0), kad_ctx.calls);

    try host.runPeriodicTicks(200);
    try testing.expect(kad_ctx.calls >= 1);
}

test "Host autonat reachability promotes kad to server mode" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
        .autonat = .{ .enable = true, .client = .{ .policy = .{ .confidence_threshold = 1, .failure_threshold = 99 } } },
    });
    defer host.destroy();

    const KadCtx = struct {
        fn noop(_: ?*anyopaque, _: []const u8, _: kad_dht_mod.MessageView, response_out: *kad_dht_mod.MessageOwned) !void {
            response_out.* = .{ .msg_type = .find_node };
        }
    };
    var me_b58_buf: [128]u8 = undefined;
    const me_b58 = try me.toBase58(&me_b58_buf);
    var kad = try kad_dht_mod.Client.init(a, me_b58, .{ .mode = .client }, KadCtx.noop);
    defer kad.deinit();
    host.setKadDhtClient(&kad);
    try testing.expect(kad.dhtMode() == .client);

    try host.recordObservedAddr("/ip4/203.0.113.9/udp/4001/quic-v1");
    try host.handleAutonatV1Response(.{ .status = .ok, .addr = "/ip4/203.0.113.9/udp/4001/quic-v1" });
    try testing.expect(kad.dhtMode() == .server);
}

test "Host mdns discovery registers peer and emits peer_discovered" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").os.tag == .wasi) return error.SkipZigTest;

    const a = testing.allocator;
    const me = try identity.PeerId.random();
    var host = try Host.create(.{
        .allocator = a,
        .local_peer = me,
        .gossipsub = .{ .local_peer_id = me },
        .mdns = .{ .enable = true, .config = .{ .live_sockets = false, .discovery_cooldown_ms = 0 } },
    });
    defer host.destroy();

    const remote = try identity.PeerId.random();
    var remote_b58_buf: [128]u8 = undefined;
    const remote_b58 = try remote.toBase58(&remote_b58_buf);
    const addr = try std.fmt.allocPrint(a, "/ip4/192.168.1.44/udp/4001/quic-v1/p2p/{s}", .{remote_b58});
    defer a.free(addr);
    const txt = try std.fmt.allocPrint(a, "dnsaddr={s}", .{addr});
    defer a.free(txt);

    const m = host.mdns_service.?;
    const packet = try discovery_mod.mdns.buildTxtResponsePacket(a, txt);
    defer a.free(packet);
    try m.handleDatagram(packet, 1_000);
    try host.runPeriodicTicks(1_000);

    try testing.expect(host.knownPeerStatus(remote) != null);

    try host.startBackground();
    _ = host.waitUntilReady(5_000);
    var saw_discovered = false;
    while (true) {
        const ev = host.nextEvent(200) catch break;
        var e = ev;
        defer e.deinit(a);
        if (std.meta.activeTag(e) == .peer_discovered) {
            saw_discovered = true;
            break;
        }
    }
    try testing.expect(saw_discovered);
}
