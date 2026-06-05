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

// toTKAKeyV1 converts an [ipnstate.TKAKey] to the JSON output returned
// by the CLI.
func ipnTKAKeytoTKAKeyV1(key *ipnstate.TKAKey) lockcmdjsonv1.Key {
	return lockcmdjsonv1.Key{
		Kind:   key.Kind,
		Votes:  key.Votes,
		Public: key.Key.CLIString(),
		Meta:   key.Metadata,
	}
}

// toTKAKeyV1 converts a [tka.Key] to the JSON output returned
// by the CLI.
func toTKAKeyV1(key *tka.Key) lockcmdjsonv1.Key {
	return lockcmdjsonv1.Key{
		Kind:   key.Kind.String(),
		Votes:  key.Votes,
		Public: fmt.Sprintf("tlpub:%x", key.Public),
		Meta:   key.Meta,
	}
}

func toTKANodeKeySignatureV1(sig *tka.NodeKeySignature) *lockcmdjsonv1.NodeKeySignature {
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
		out.Nested = toTKANodeKeySignatureV1(sig.Nested)
	}
	if len(sig.WrappingPubkey) > 0 {
		out.WrappingPublicKey = fmt.Sprintf("tlpub:%x", sig.WrappingPubkey)
	}
	return &out
}

func toTKAPeerV1(peer *ipnstate.TKAPeer) lockcmdjsonv1.Peer {
	out := lockcmdjsonv1.Peer{
		DNSName: peer.Name,
		ID:      string(peer.StableID),
		NodeKey: peer.NodeKey.String(),
	}
	for _, ip := range peer.TailscaleIPs {
		out.TailscaleIPs = append(out.TailscaleIPs, ip.String())
	}
	return out
}

func toTrustedTKAPeerV1(peer *ipnstate.TKAPeer) lockcmdjsonv1.TrustedPeer {
	out := toTKAPeerV1(peer)
	return lockcmdjsonv1.TrustedPeer{
		DNSName:          out.DNSName,
		ID:               out.ID,
		TailscaleIPs:     out.TailscaleIPs,
		NodeKey:          out.NodeKey,
		NodeKeySignature: toTKANodeKeySignatureV1(&peer.NodeKeySignature),
	}
}
