package dviewrand

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"

	"github.com/gordian-engine/dragon/daddr"
	"github.com/gordian-engine/dragon/dcert"
	"github.com/gordian-engine/dragon/dview"
)

// Manager is a randomness-based [dview.Manager],
// closely following the behavior specified in the HyParView whitepaper.
type Manager struct {
	log *slog.Logger

	rng *rand.Rand

	aLimit, pLimit int

	aByCA map[dcert.CACertHandle]*dview.ActivePeer
	pByCA map[dcert.CACertHandle]*dview.PassivePeer
}

type Config struct {
	// Target sizes for active and passive views.
	ActiveViewSize, PassiveViewSize int

	// The RNG is used for randomness in decisions.
	RNG *rand.Rand
}

// New returns a new Manager.
func New(log *slog.Logger, cfg Config) *Manager {
	if cfg.ActiveViewSize <= 0 {
		panic(fmt.Errorf(
			"Config.ActiveViewSize must be positive (got %d)", cfg.ActiveViewSize,
		))
	}

	if cfg.PassiveViewSize <= 0 {
		panic(fmt.Errorf(
			"Config.PassiveViewSize must be positive (got %d)", cfg.PassiveViewSize,
		))
	}

	if cfg.RNG == nil {
		panic(errors.New("BUG: Config.RNG must not be nil"))
	}

	return &Manager{
		log: log,

		rng: cfg.RNG,

		aLimit: cfg.ActiveViewSize,
		pLimit: cfg.PassiveViewSize,

		// These are both +1 to account for bursting an additional peer.
		// They should only need +1 due to methods being called serially.
		aByCA: make(map[dcert.CACertHandle]*dview.ActivePeer, cfg.ActiveViewSize+1),
		pByCA: make(map[dcert.CACertHandle]*dview.PassivePeer, cfg.PassiveViewSize+1),
	}
}

// ConsiderJoin accepts the peer if there is no existing active peer
// from the same trusted CA, or if the existing peer may be stale
// (e.g. after a crash). When a peer with the same CA already exists,
// we accept the join so that AddActivePeer can replace the stale entry.
func (m *Manager) ConsiderJoin(
	_ context.Context, p dview.ActivePeer,
) (dview.JoinDecision, error) {
	if existing, ok := m.aByCA[p.Chain.RootHandle]; ok {
		// We already have an active peer from this CA.
		// Accept anyway — the old connection may be stale (peer crashed).
		// AddActivePeer will handle evicting the old entry.
		m.log.Info(
			"Accepting join from peer with existing CA (possible reconnection)",
			"existing_remote_addr", existing.RemoteAddr.String(),
			"new_remote_addr", p.RemoteAddr.String(),
		)
		return dview.AcceptJoinDecision, nil
	}

	// Otherwise it's acceptable.
	return dview.AcceptJoinDecision, nil
}

// ConsiderNeighborRequest accepts the request.
// If a peer with the same CA already exists, we still accept
// because the old connection may be stale (peer crashed and reconnected).
func (m *Manager) ConsiderNeighborRequest(
	_ context.Context, p dview.ActivePeer,
) (bool, error) {
	return true, nil
}

// ConsiderForwardJoin always continues forwarding,
// and always wants to connect to the neighbor
// (even if we already have one from the same CA, since it may be stale).
func (m *Manager) ConsiderForwardJoin(
	_ context.Context, aa daddr.AddressAttestation, chain dcert.Chain,
) (dview.ForwardJoinDecision, error) {
	return dview.ForwardJoinDecision{
		ContinueForwarding:  true,
		MakeNeighborRequest: true,
	}, nil
}

func (m *Manager) AddActivePeer(
	_ context.Context, p dview.ActivePeer,
) (evicted *dview.ActivePeer, err error) {
	sameCAReplace := false
	if _, ok := m.aByCA[p.Chain.RootHandle]; ok {
		// Peer with same CA exists (crash recovery reconnection).
		// Update our internal map but don't return evicted — the ActiveView
		// will handle closing the old connection when it processes the add.
		// Returning evicted for same-CA replacement causes the kernel to call
		// av.Remove(evicted) which looks up by CA handle, removing the NEW peer.
		m.log.Info(
			"Replacing peer with same CA in view manager (crash recovery)",
			"ca_handle", p.Chain.RootHandle.String(),
			"new_remote_addr", p.RemoteAddr.String(),
		)
		delete(m.aByCA, p.Chain.RootHandle)
		sameCAReplace = true
	}

	// If we are at the active limit (and didn't already free a slot above),
	// we need to pick a peer to evict. This evicts a DIFFERENT CA,
	// so it's safe for the kernel to call av.Remove on it.
	if !sameCAReplace && len(m.aByCA) >= m.aLimit {
		var deleteActiveKey dcert.CACertHandle
		deleteActiveKey, evicted = m.randomActivePeer()
		delete(m.aByCA, deleteActiveKey)
	}

	m.aByCA[p.Chain.RootHandle] = &p

	// We can just attempt to delete the passive peer if one exists,
	// without doing a lookup first.
	delete(m.pByCA, p.Chain.RootHandle)
	return evicted, nil
}

func (m *Manager) RemoveActivePeer(_ context.Context, p dview.ActivePeer) {
	if _, ok := m.aByCA[p.Chain.RootHandle]; !ok {
		// Peer was already removed (e.g. replaced during crash recovery).
		m.log.Info(
			"Peer already removed from active set (possible crash recovery cleanup)",
			"ca_handle", p.Chain.RootHandle.String(),
		)
		return
	}

	delete(m.aByCA, p.Chain.RootHandle)
}

func (m *Manager) randomActivePeer() (dcert.CACertHandle, *dview.ActivePeer) {
	// Map iteration order simply is unspecified, not random,
	// so use the RNG to pick.
	more := m.rng.IntN(len(m.aByCA))
	for k, p := range m.aByCA {
		if more == 0 {
			return k, p
		}
		more--
	}

	// Map was empty.
	return dcert.CACertHandle{}, nil
}

func (m *Manager) randomPassivePeer() (dcert.CACertHandle, *dview.PassivePeer) {
	// Map iteration order simply is unspecified, not random,
	// so use the RNG to pick.
	more := m.rng.IntN(len(m.aByCA))
	for k, p := range m.pByCA {
		if more == 0 {
			return k, p
		}
		more--
	}

	// Map was empty.
	return dcert.CACertHandle{}, nil
}

func (m *Manager) MakeOutboundShuffle(ctx context.Context) (dview.OutboundShuffle, error) {
	return dview.OutboundShuffle{}, errors.New("TODO")
}

func (m *Manager) MakeShuffleResponse(
	ctx context.Context, src dcert.Chain, entries []dview.ShuffleEntry,
) ([]dview.ShuffleEntry, error) {
	return nil, errors.New("TODO")
}

func (m *Manager) HandleShuffleResponse(
	ctx context.Context, src dcert.Chain, entries []dview.ShuffleEntry,
) error {
	return errors.New("TODO")
}

func (m *Manager) NActivePeers() int {
	return len(m.aByCA)
}

func (m *Manager) NPassivePeers() int {
	return len(m.pByCA)
}
