// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package lockcmdjsonv1

import (
	jsonv1 "encoding/json"
	"io"

	"tailscale.com/cmd/tailscale/cli/jsonoutput"
	"tailscale.com/cmd/tailscale/cli/jsonoutput/lockcmdjsonv1"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
)

// PrintNetworkLockStatusJSONV1 prints the current Tailnet Lock status
// as a JSON object to the CLI, in a stable "v1" format.
func PrintNetworkLockStatusJSONV1(out io.Writer, status *ipnstate.NetworkLockStatus) error {
	responseEnvelope := jsonoutput.ResponseEnvelope{
		SchemaVersion: "1",
	}

	var result lockcmdjsonv1.StatusResponse
	if status.Enabled {
		result = toTailnetLockEnabledStatusV1(status)
		result.ResponseEnvelope = responseEnvelope
	} else {
		result = toTailnetLockDisabledStatusV1(status)
		result.ResponseEnvelope = responseEnvelope
	}

	enc := jsonv1.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func toTailnetLockDisabledStatusV1(status *ipnstate.NetworkLockStatus) lockcmdjsonv1.StatusResponse {
	out := lockcmdjsonv1.StatusResponse{
		Enabled: status.Enabled,
	}
	if !status.PublicKey.IsZero() {
		out.PublicKey = status.PublicKey.CLIString()
	}
	if nk := status.NodeKey; nk != nil {
		out.NodeKey = nk.String()
	}
	return out
}

func toTailnetLockEnabledStatusV1(status *ipnstate.NetworkLockStatus) lockcmdjsonv1.StatusResponse {
	out := lockcmdjsonv1.StatusResponse{
		Enabled: status.Enabled,
	}

	if status.Head != nil {
		var head tka.AUMHash
		h := status.Head
		copy(head[:], h[:])
		out.Head = head.String()
	}
	if !status.PublicKey.IsZero() {
		out.PublicKey = status.PublicKey.CLIString()
	}
	if nk := status.NodeKey; nk != nil {
		out.NodeKey = nk.String()
	}
	out.NodeKeySigned = &status.NodeKeySigned
	if sig := status.NodeKeySignature; sig != nil {
		out.NodeKeySignature = toTKANodeKeySignatureV1(sig)
	}
	for _, key := range status.TrustedKeys {
		out.TrustedKeys = append(out.TrustedKeys, ipnTKAKeytoTKAKeyV1(&key))
	}
	for _, vp := range status.VisiblePeers {
		out.VisiblePeers = append(out.VisiblePeers, toTrustedTKAPeerV1(vp))
	}
	for _, fp := range status.FilteredPeers {
		out.FilteredPeers = append(out.FilteredPeers, toTKAPeerV1(fp))
	}
	out.StateID = status.StateID

	return out
}
