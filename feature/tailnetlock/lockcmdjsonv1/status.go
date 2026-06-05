// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package lockcmdjsonv1

import (
	"tailscale.com/cmd/tailscale/cli/jsonoutput"
	"tailscale.com/cmd/tailscale/cli/jsonoutput/lockcmdjsonv1"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
)

// StatusResponse returns the current Tailnet Lock status as a JSON object to the CLI,
// in a stable "v1" format.
func StatusResponse(status *ipnstate.NetworkLockStatus) lockcmdjsonv1.StatusResponse {
	out := lockcmdjsonv1.StatusResponse{
		ResponseEnvelope: jsonoutput.ResponseEnvelope{
			SchemaVersion: "1",
		},
		Enabled: status.Enabled,
	}
	if !status.PublicKey.IsZero() {
		out.PublicKey = status.PublicKey.CLIString()
	}
	if nk := status.NodeKey; nk != nil {
		out.NodeKey = nk.String()
	}
	if !status.Enabled {
		return out // Tailnet Lock is disabled, omit the following fields
	}

	if status.Head != nil {
		var head tka.AUMHash
		h := status.Head
		copy(head[:], h[:])
		out.Head = head.String()
	}
	out.NodeKeySigned = &status.NodeKeySigned
	if sig := status.NodeKeySignature; sig != nil {
		out.NodeKeySignature = nodeKeySignature(sig)
	}
	for _, key := range status.TrustedKeys {
		out.TrustedKeys = append(out.TrustedKeys, ipnTKAKey(&key))
	}
	for _, vp := range status.VisiblePeers {
		out.VisiblePeers = append(out.VisiblePeers, trustedPeer(vp))
	}
	for _, fp := range status.FilteredPeers {
		out.FilteredPeers = append(out.FilteredPeers, peer(fp))
	}
	out.StateID = status.StateID
	return out
}
