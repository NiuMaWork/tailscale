// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package lockcmdjsonv1

import (
	"encoding/base64"
	"fmt"

	"tailscale.com/cmd/tailscale/cli/jsonoutput/lockcmdjsonv1"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
)

// ipnTKAKey converts an [ipnstate.TKAKey] to the JSON output returned by the CLI,
// in a stable "v1" format.
func ipnTKAKey(key *ipnstate.TKAKey) lockcmdjsonv1.Key {
	return lockcmdjsonv1.Key{
		Kind:   key.Kind,
		Votes:  key.Votes,
		Public: key.Key.CLIString(),
		Meta:   key.Metadata,
	}
}

// tkaKey converts a [tka.Key] to the JSON output returned by the CLI,
// in a stable "v1" format.
func tkaKey(key *tka.Key) lockcmdjsonv1.Key {
	return lockcmdjsonv1.Key{
		Kind:   key.Kind.String(),
		Votes:  key.Votes,
		Public: fmt.Sprintf("tlpub:%x", key.Public),
		Meta:   key.Meta,
	}
}

// nodeKeySignature converts a [tka.NodeKeySignature] to the JSON output returned by the CLI,
// in a stable "v1" format.
func nodeKeySignature(sig *tka.NodeKeySignature) *lockcmdjsonv1.NodeKeySignature {
	out := lockcmdjsonv1.NodeKeySignature{
		SigKind: sig.SigKind.String(),
	}
	if len(sig.Pubkey) > 0 {
		out.PublicKey = fmt.Sprintf("tlpub:%x", sig.Pubkey)
	}
	if len(sig.KeyID) > 0 {
		out.KeyID = fmt.Sprintf("tlpub:%x", sig.KeyID)
	}
	out.Signature = base64.URLEncoding.EncodeToString(sig.Signature)
	if sig.Nested != nil {
		out.Nested = nodeKeySignature(sig.Nested)
	}
	if len(sig.WrappingPubkey) > 0 {
		out.WrappingPublicKey = fmt.Sprintf("tlpub:%x", sig.WrappingPubkey)
	}
	return &out
}

// peer converts a [ipnstate.TKAPeer] to the JSON output returned by the CLI,
// in a stable "v1" format.
func peer(p *ipnstate.TKAPeer) lockcmdjsonv1.Peer {
	out := lockcmdjsonv1.Peer{
		DNSName: p.Name,
		ID:      string(p.StableID),
		NodeKey: p.NodeKey.String(),
	}
	for _, ip := range p.TailscaleIPs {
		out.TailscaleIPs = append(out.TailscaleIPs, ip.String())
	}
	return out
}

// trustedPeer converts a trusted [ipnstate.TKAPeer] to the JSON output returned by the CLI,
// in a stable "v1" format.
func trustedPeer(p *ipnstate.TKAPeer) lockcmdjsonv1.TrustedPeer {
	out := peer(p)
	return lockcmdjsonv1.TrustedPeer{
		DNSName:          out.DNSName,
		ID:               out.ID,
		TailscaleIPs:     out.TailscaleIPs,
		NodeKey:          out.NodeKey,
		NodeKeySignature: nodeKeySignature(&p.NodeKeySignature),
	}
}
