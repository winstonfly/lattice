// Copyright 2026 The Lattice Authors, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import "github.com/spf13/cobra"

// AgentCmd returns the top-level `agent` cobra command.
func AgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage AI agent sandboxes",
		Long: `The agent commands start and configure AI agent sandboxes on the
Lattice overlay network.

All sandbox traffic flows through a gVisor userspace network stack — no kernel
WireGuard interface (wg0) is created on the host.

Scenarios:
  agent run    — single container, requires --runtime=runsc (or equivalent)
  agent sidecar — Kubernetes sidecar with transparent proxy
  agent init   — Kubernetes init container, writes iptables rules and exits`,
	}
	addRunCmd(cmd)
	addSidecarCmd(cmd)
	addInitCmd(cmd)
	return cmd
}
