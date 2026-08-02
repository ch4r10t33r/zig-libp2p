//! Typed payloads for peer connection / disconnection / dial failure events (#38).

const errors = @import("../primitives/errors.zig");
const identity = @import("../primitives/identity.zig");

pub const Direction = enum {
    inbound,
    outbound,
    /// Transport has not classified direction yet (#38).
    unknown,
};

pub const DisconnectReason = enum {
    timeout,
    remote_close,
    local_close,
    err,
    /// Synthesized by the reconciliation sweep (#299): the connection manager
    /// still tracked the conn but the transport no longer had a live leg for
    /// it — the real close event was lost (e.g. dropped on coordinator-queue
    /// allocation failure) or never detected. Distinct from `remote_close` so
    /// embedders and logs can see that the peer book drifted and was repaired.
    orphaned,
};

/// Dial or transport handshake failure (distinct from [`DisconnectReason`] on an established conn).
pub const ConnectionFailureResult = union(enum) {
    timeout,
    err: errors.TransportError,
};

pub const PeerConnectedPayload = struct {
    peer: identity.PeerId,
    direction: Direction,
    /// True when the session rides a circuit-relay v2 hop (#205).
    via_relay: bool = false,
};

pub const PeerDisconnectedPayload = struct {
    peer: identity.PeerId,
    direction: Direction,
    reason: DisconnectReason,
};

pub const PeerConnectionFailedPayload = struct {
    peer: ?identity.PeerId,
    direction: Direction,
    result: ConnectionFailureResult,
};

pub const DiscoverySource = enum {
    mdns,
    rendezvous,
};

pub const PeerDiscoveredPayload = struct {
    peer: identity.PeerId,
    addrs: [][]const u8,
    source: DiscoverySource,
    /// Rendezvous namespace when [`source`] is `.rendezvous` (#209).
    namespace: ?[]const u8 = null,
};
