//go:build pro && linux

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

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	latticeagent "github.com/alatticeio/lattice/internal/agent"
	agentconfig "github.com/alatticeio/lattice/internal/agent/config"
	"github.com/alatticeio/lattice/internal/agent/infra"
	agentlog "github.com/alatticeio/lattice/internal/agent/log"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	runServerURL   string
	runToken       string
	runReadyWait   time.Duration
	runEgressAllow string
	runEgressDeny  bool
)

func addRunCmd(parent *cobra.Command) {
	parent.AddCommand(runCmd())
}

func runCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run <name> -- <command> [args...]",
		Short: "Run an AI agent inside a gVisor sandbox (Pro)",
		Long: `Run registers a sandbox with the Lattice control plane, starts a WireGuard
node, optionally applies egress policy via iptables inside the gVisor container,
then forks the given command.

The container must run under gVisor (--runtime=runsc or runtimeClassName: gvisor).

Example:
  docker run --runtime=runsc ghcr.io/alattice/lattice \
    agent run my-agent --server-url http://latticed:8080 --token lt-xxx \
    --egress-allow 10.0.0.0/8 --egress-default-deny \
    -- python agent.py`,
		Args: cobra.ArbitraryArgs,
		RunE: runRun,
	}
	cmd.Flags().StringVar(&runServerURL, "server-url", "", "Lattice control plane URL (required)")
	cmd.Flags().StringVar(&runToken, "token", "", "Enrollment token (required)")
	cmd.Flags().DurationVar(&runReadyWait, "ready-wait", 3*time.Second,
		"Time to wait for WireGuard peer sessions before starting the AI agent")
	cmd.Flags().StringVar(&runEgressAllow, "egress-allow", "",
		"Comma-separated overlay CIDRs the AI agent is allowed to reach (Pro)")
	cmd.Flags().BoolVar(&runEgressDeny, "egress-default-deny", false,
		"Deny all egress except --egress-allow CIDRs (Pro)")
	_ = cmd.MarkFlagRequired("server-url")
	_ = cmd.MarkFlagRequired("token")
	return cmd
}

func runRun(_ *cobra.Command, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: lattice agent run <name> -- <command> [args...]")
	}
	agentName := args[0]
	cmdArgs := args[1:]

	if runEgressDeny {
		if _, err := parseEgressCIDRs(runEgressAllow); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentconfig.Conf.AppId = agentName
	agentconfig.Conf.ServerUrl = runServerURL
	agentconfig.Conf.WgPort = 51820

	_ = os.MkdirAll("/dev/net", 0o755)

	currentPeer, err := registerOrResume(ctx, agentName, runServerURL, runToken)
	if err != nil {
		return err
	}

	localIP := overlayAddr(currentPeer)
	fmt.Printf("[agent-run] %q registered, overlay IP=%s\n", agentName, localIP)

	if currentPeer.LrpUrl != "" {
		agentconfig.Conf.EnableLrp = true
		agentconfig.Conf.RelayURL = currentPeer.LrpUrl
	}

	logger := agentlog.GetLogger("agent-run")
	agentJWT := currentPeer.Token

	nodeCfg := &latticeagent.NodeConfig{
		Logger:      logger,
		Port:        51820,
		ShowLog:     false,
		Flags:       agentconfig.Conf,
		CustomName:  agentName,
		CurrentPeer: currentPeer,
	}

	node, err := latticeagent.NewNode(ctx, nodeCfg)
	if err != nil {
		return fmt.Errorf("create node: %w", err)
	}

	node.GetNetworkMap = func() (*infra.Message, error) {
		msg, getErr := node.GetNetMap(agentJWT)
		if getErr != nil {
			logger.Error("get network map failed", getErr)
			return nil, getErr
		}
		return msg, nil
	}

	if err = node.Start(ctx); err != nil {
		return fmt.Errorf("start node: %w", err)
	}
	defer node.Stop() //nolint:errcheck

	go node.StartHeartbeat(ctx)
	go runPeriodicRefresh(ctx, node, logger)

	select {
	case <-time.After(runReadyWait):
	case <-ctx.Done():
		return ctx.Err()
	}

	if runEgressDeny {
		cidrs, _ := parseEgressCIDRs(runEgressAllow) // already validated above
		if err := applyEgressIPTables(cidrs); err != nil {
			return fmt.Errorf("apply egress iptables: %w", err)
		}
	}

	return forkAndWait(ctx, cancel, cmdArgs)
}

// registerOrResume tries to resume from persisted credentials; falls back to
// fresh NATS registration.
func registerOrResume(ctx context.Context, agentName, serverURL, token string) (*infra.Peer, error) {
	if creds, err := loadSandboxCredentials(); err == nil {
		if key, parseErr := wgtypes.ParseKey(creds.PrivateKey); parseErr == nil {
			if peer, resumeErr := latticeagent.ResumeSandboxViaNATS(ctx, serverURL, creds.JWT, agentName, key); resumeErr == nil {
				fmt.Printf("[agent-run] resumed %q from saved credentials\n", agentName)
				return peer, nil
			}
		}
	}

	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate WireGuard key: %w", err)
	}
	peer, err := latticeagent.RegisterSandboxViaNATS(ctx, serverURL, token, agentName, privKey)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}
	if saveErr := saveSandboxCredentials(privKey, peer.Token); saveErr != nil {
		fmt.Printf("[agent-run] warning: persist credentials: %v\n", saveErr)
	}
	return peer, nil
}

// runPeriodicRefresh polls the network map every 15 s as a NATS push fallback.
func runPeriodicRefresh(ctx context.Context, node *latticeagent.Node, logger interface {
	Warn(msg string, args ...any)
}) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := node.RefreshConfig(ctx); err != nil {
				logger.Warn("periodic config refresh failed", "err", err)
			}
		}
	}
}

// forkAndWait forks cmdArgs[0] as a child process, waits for it to exit, and
// propagates the exit code. cancel is called when the child exits so the node
// is cleaned up.
func forkAndWait(ctx context.Context, cancel context.CancelFunc, cmdArgs []string) error {
	child := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = os.Environ()

	if err := child.Start(); err != nil {
		return fmt.Errorf("start agent process: %w", err)
	}

	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var childErr error
	select {
	case childErr = <-childDone:
		cancel()
	case <-sigCh:
		_ = child.Process.Signal(syscall.SIGTERM)
		select {
		case childErr = <-childDone:
		case <-time.After(5 * time.Second):
			_ = child.Process.Kill()
			childErr = <-childDone
		}
		cancel()
	}

	var exitErr *exec.ExitError
	if errors.As(childErr, &exitErr) {
		os.Exit(exitErr.ExitCode())
	}
	return childErr
}

// parseEgressCIDRs splits and validates a comma-separated CIDR string.
func parseEgressCIDRs(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var out []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return nil, fmt.Errorf("invalid egress CIDR %q: %w", entry, err)
		}
		out = append(out, entry)
	}
	return out, nil
}

// applyEgressIPTables installs iptables rules inside the gVisor container to
// restrict egress traffic on the overlay. gVisor virtualises iptables, so
// these rules apply to gVisor's netstack.
func applyEgressIPTables(allowCIDRs []string) error {
	rules := [][]string{
		// Allow established/related connections.
		{"-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		// Allow loopback.
		{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
		// Allow WireGuard encrypted UDP (to peer endpoints).
		{"-A", "OUTPUT", "-p", "udp", "-j", "ACCEPT"},
	}
	for _, cidr := range allowCIDRs {
		rules = append(rules, []string{"-A", "OUTPUT", "-d", cidr, "-j", "ACCEPT"})
	}
	rules = append(rules, []string{"-P", "OUTPUT", "DROP"})

	for _, args := range rules {
		out, err := exec.Command("iptables", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables %v: %s: %w", args, out, err)
		}
	}
	return nil
}
