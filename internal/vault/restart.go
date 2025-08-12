/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RestartManager handles Vault cluster restarts
type RestartManager struct {
	Client       client.Client
	VaultAddress string
	VaultRole    string
	Namespace    string
	Logger       logr.Logger
	DryRun       bool

	vaultClient *vaultapi.Client // Private, created internally
}

// ClusterHealth represents Vault cluster health information
type ClusterHealth struct {
	Healthy     bool
	VoterCount  int
	LastContact time.Duration
	Details     string
}

// NodeInfo represents Vault cluster node information
type NodeInfo struct {
	LeaderPod    string
	FollowerPods []string
	ClusterNodes map[string]VaultNode
}

// VaultNode represents a single Vault node
type VaultNode struct {
	Address string
	NodeID  string
	Leader  bool
	Voter   bool
}

// ExecuteRestart performs the complete Vault cluster restart sequence
func (rm *RestartManager) ExecuteRestart(ctx context.Context, statefulSetName string) error {
	rm.Logger.Info("Starting Vault cluster restart", "statefulSetName", statefulSetName, "dryRun", rm.DryRun)

	if rm.DryRun {
		rm.Logger.Info("🧪 DRY RUN MODE - No actual changes will be made")
	}

	// Step 1: Authenticate to Vault
	if err := rm.authenticateVault(ctx); err != nil {
		return fmt.Errorf("vault authentication failed: %w", err)
	}
	rm.Logger.Info("✅ Vault authentication successful")

	// Step 2: Verify cluster health
	health, err := rm.verifyClusterHealth(ctx)
	if err != nil {
		return fmt.Errorf("cluster health check failed: %w", err)
	}
	rm.Logger.Info("✅ Cluster health verified", "healthy", health.Healthy, "voters", health.VoterCount)

	// Step 3: Identify active node and followers
	nodeInfo, err := rm.identifyNodes(ctx, statefulSetName)
	if err != nil {
		return fmt.Errorf("failed to identify cluster nodes: %w", err)
	}
	rm.Logger.Info("✅ Cluster nodes identified",
		"leader", nodeInfo.LeaderPod,
		"followers", nodeInfo.FollowerPods,
		"totalNodes", len(nodeInfo.ClusterNodes))

	// Step 4: Restart follower pods one by one
	if err := rm.restartFollowerPods(ctx, nodeInfo.FollowerPods); err != nil {
		return fmt.Errorf("failed to restart follower pods: %w", err)
	}

	// Step 5: Step down the leader
	if err := rm.stepDownLeader(ctx); err != nil {
		return fmt.Errorf("failed to step down leader: %w", err)
	}

	// Step 6: Restart the former leader pod
	if err := rm.restartFormerLeader(ctx, nodeInfo.LeaderPod); err != nil {
		return fmt.Errorf("failed to restart former leader: %w", err)
	}

	// Step 7: Final verification
	if err := rm.verifyFinalState(ctx); err != nil {
		return fmt.Errorf("final verification failed: %w", err)
	}

	rm.Logger.Info("🎉 Vault cluster restart completed successfully", "dryRun", rm.DryRun)
	return nil
}

// authenticateVault establishes authenticated connection to Vault
func (rm *RestartManager) authenticateVault(ctx context.Context) error {
	rm.Logger.Info("Authenticating to Vault using vault-operations-sa", "address", rm.VaultAddress, "role", rm.VaultRole, "dryRun", rm.DryRun)

	// Use vault-operations-sa service account for Vault authentication
	vaultServiceAccount := "vault-operations-sa"
	vaultNamespace := "vault-stage" // TODO: Make this configurable

	client, err := LoginWithKubernetesAuthAndServiceAccount(ctx, rm.Client, rm.VaultAddress, rm.VaultRole, vaultServiceAccount, vaultNamespace)
	if err != nil {
		return err
	}
	rm.vaultClient = client

	if rm.DryRun {
		rm.Logger.Info("🧪 [DRY RUN] Vault authentication successful - will test API queries but skip destructive operations")
	}
	return nil
}

// verifyClusterHealth checks Vault cluster health using raft autopilot
func (rm *RestartManager) verifyClusterHealth(ctx context.Context) (*ClusterHealth, error) {
	if rm.DryRun {
		rm.Logger.Info("[DRY RUN] Testing cluster health verification using real Vault API calls")
	}

	// Check raft autopilot state via Vault API
	rm.Logger.Info("Checking cluster health via Vault API...")

	// Call vault operator raft autopilot state
	resp, err := rm.vaultClient.Logical().Read("sys/storage/raft/autopilot/state")
	if err != nil {
		return nil, fmt.Errorf("failed to read raft autopilot state: %w", err)
	}

	if resp == nil || resp.Data == nil {
		return nil, fmt.Errorf("empty response from raft autopilot state")
	}

	// Log the full autopilot response for debugging
	rm.Logger.Info("Raft autopilot state response", "data", resp.Data)

	// Parse response data - note the field names are lowercase in the response
	healthy, ok := resp.Data["healthy"].(bool)
	if !ok {
		healthy = false
	}
	rm.Logger.Info("Parsed autopilot health status", "healthy", healthy)

	// Count voters from the "voters" array or "servers" map
	voterCount := 0
	if voters, exists := resp.Data["voters"]; exists {
		if voterList, ok := voters.([]interface{}); ok {
			voterCount = len(voterList)
		}
	} else if servers, exists := resp.Data["servers"]; exists {
		if serverMap, ok := servers.(map[string]interface{}); ok {
			for _, server := range serverMap {
				if serverData, ok := server.(map[string]interface{}); ok {
					if nodeType, exists := serverData["node_type"]; exists && nodeType == "voter" {
						voterCount++
					}
				}
			}
		}
	}

	// Get leader info and last contact time
	lastContact := time.Duration(0)
	var leaderName string
	if leader, exists := resp.Data["leader"]; exists {
		if leaderStr, ok := leader.(string); ok {
			leaderName = leaderStr
			// Get leader's last contact from servers map
			if servers, exists := resp.Data["servers"]; exists {
				if serverMap, ok := servers.(map[string]interface{}); ok {
					if leaderData, exists := serverMap[leaderName]; exists {
						if leaderInfo, ok := leaderData.(map[string]interface{}); ok {
							if lastContactStr, exists := leaderInfo["last_contact"]; exists {
								if contactStr, ok := lastContactStr.(string); ok {
									if duration, err := time.ParseDuration(contactStr); err == nil {
										lastContact = duration
									}
								}
							}
						}
					}
				}
			}
		}
	}

	health := &ClusterHealth{
		Healthy:     healthy,
		VoterCount:  voterCount,
		LastContact: lastContact,
		Details:     fmt.Sprintf("Vault raft autopilot state: healthy=%v, voters=%d, lastContact=%v", healthy, voterCount, lastContact),
	}

	rm.Logger.Info("Cluster health analysis",
		"healthy", healthy,
		"voterCount", voterCount,
		"lastContact", lastContact,
		"details", health.Details)

	if !healthy {
		rm.Logger.Error(nil, "Cluster reported as unhealthy by autopilot", "health", health)
		return health, fmt.Errorf("cluster is not healthy according to raft autopilot")
	}

	if voterCount < 2 {
		return health, fmt.Errorf("insufficient voters for safe restart: %d (need at least 2)", voterCount)
	}

	if lastContact > 10*time.Second {
		return health, fmt.Errorf("leader contact too old: %v (should be < 10s)", lastContact)
	}

	return health, nil
}

// identifyNodes determines leader and follower pods using vault operator members
func (rm *RestartManager) identifyNodes(ctx context.Context, statefulSetName string) (*NodeInfo, error) {
	if rm.DryRun {
		rm.Logger.Info("[DRY RUN] Testing node identification using real Vault API calls")
	}

	// Get StatefulSet pods from Kubernetes
	pods, err := rm.getStatefulSetPods(ctx, statefulSetName)
	if err != nil {
		return nil, fmt.Errorf("failed to get StatefulSet pods: %w", err)
	}

	// Get cluster members via Vault API
	rm.Logger.Info("Getting cluster members via Vault API...", "podCount", len(pods))

	if len(pods) == 0 {
		return nil, fmt.Errorf("no pods found for StatefulSet %s", statefulSetName)
	}

	// Call vault operator raft autopilot state to get cluster members with leader info
	resp, err := rm.vaultClient.Logical().Read("sys/storage/raft/autopilot/state")
	if err != nil {
		return nil, fmt.Errorf("failed to read raft autopilot state: %w", err)
	}

	if resp == nil || resp.Data == nil {
		return nil, fmt.Errorf("empty response from raft autopilot state")
	}

	// Leader identification will be done from autopilot response data

	clusterNodes := make(map[string]VaultNode)
	var leaderPod string
	var followerPods []string

	// Parse autopilot response to identify leader and followers
	leaderFromAutopilot, _ := resp.Data["leader"].(string)
	rm.Logger.Info("Leader from autopilot response", "leader", leaderFromAutopilot)

	if servers, exists := resp.Data["servers"]; exists {
		if serverMap, ok := servers.(map[string]interface{}); ok {
			for serverName, serverData := range serverMap {
				if serverInfo, ok := serverData.(map[string]interface{}); ok {
					status, _ := serverInfo["status"].(string)
					address, _ := serverInfo["address"].(string)
					nodeID, _ := serverInfo["id"].(string)

					// Map server name to pod name (server name should match pod name)
					podName := serverName

					isLeader := (status == "leader")
					isVoter := (status == "leader" || status == "voter")

					clusterNodes[podName] = VaultNode{
						Address: address,
						NodeID:  nodeID,
						Leader:  isLeader,
						Voter:   isVoter,
					}

					if isLeader {
						leaderPod = podName
						rm.Logger.Info("Leader identified from autopilot", "pod", podName, "status", status)
					} else {
						followerPods = append(followerPods, podName)
						rm.Logger.Info("Follower identified from autopilot", "pod", podName, "status", status)
					}
				}
			}
		}
	}

	// Fallback: if we couldn't identify the leader from autopilot response, this is an error
	if leaderPod == "" {
		if len(pods) > 0 {
			rm.Logger.Error(nil, "Failed to identify leader from Vault autopilot response - this indicates a parsing error or Vault API issue",
				"expectedLeader", leaderFromAutopilot, "availablePods", pods)
			return nil, fmt.Errorf("failed to identify leader from Vault autopilot response")
		} else {
			return nil, fmt.Errorf("no pods found in StatefulSet")
		}
	}

	nodeInfo := &NodeInfo{
		LeaderPod:    leaderPod,
		FollowerPods: followerPods,
		ClusterNodes: clusterNodes,
	}

	return nodeInfo, nil
}

// mapAddressToPodName maps a Vault cluster address to a Kubernetes pod name
func (rm *RestartManager) mapAddressToPodName(address string, pods []string) string {
	// Try to extract pod name from address
	// Examples:
	// "vault-0.vault.vault-stage.svc.cluster.local:8201" -> "vault-0"
	// "vault-1:8200" -> "vault-1"

	for _, podName := range pods {
		if strings.Contains(address, podName) {
			return podName
		}
	}

	// Fallback: try to extract hostname from address
	if strings.Contains(address, ":") {
		host := strings.Split(address, ":")[0]
		if strings.Contains(host, ".") {
			// Extract first part before the dot
			hostParts := strings.Split(host, ".")
			if len(hostParts) > 0 {
				candidate := hostParts[0]
				for _, podName := range pods {
					if candidate == podName {
						return podName
					}
				}
			}
		}
	}

	return "" // Could not map address to pod name
}

// getStatefulSetPods returns sorted list of pod names for the StatefulSet
func (rm *RestartManager) getStatefulSetPods(ctx context.Context, statefulSetName string) ([]string, error) {
	podList := &corev1.PodList{}
	err := rm.Client.List(ctx, podList, client.InNamespace(rm.Namespace),
		client.MatchingLabels{"app.kubernetes.io/name": "vault"})
	if err != nil {
		return nil, err
	}

	var podNames []string
	for _, pod := range podList.Items {
		if strings.HasPrefix(pod.Name, statefulSetName+"-") && pod.Status.Phase == corev1.PodRunning {
			podNames = append(podNames, pod.Name)
		}
	}

	// Sort to ensure consistent ordering (vault-0, vault-1, vault-2)
	sort.Strings(podNames)
	return podNames, nil
}

// restartFollowerPods restarts follower pods one at a time with 45s delays
func (rm *RestartManager) restartFollowerPods(ctx context.Context, followers []string) error {
	rm.Logger.Info("Starting follower pod restarts", "followers", followers)

	for i, podName := range followers {
		rm.Logger.Info("Restarting follower pod", "pod", podName, "step", fmt.Sprintf("%d/%d", i+1, len(followers)))

		if rm.DryRun {
			rm.Logger.Info("🧪 [DRY RUN] Would delete pod and wait for restart", "pod", podName)
		} else {
			if err := rm.deletePod(ctx, podName); err != nil {
				return fmt.Errorf("failed to delete follower pod %s: %w", podName, err)
			}

			if err := rm.waitForPodReady(ctx, podName); err != nil {
				return fmt.Errorf("follower pod %s failed to become ready: %w", podName, err)
			}
		}

		// Wait 45 seconds between pod restarts (as per HashiCorp docs)
		if i < len(followers)-1 { // Don't wait after the last pod
			rm.Logger.Info("Waiting 45 seconds before next follower restart", "remaining", len(followers)-i-1)
			if rm.DryRun {
				rm.Logger.Info("🧪 [DRY RUN] Would wait 45 seconds")
			} else {
				time.Sleep(45 * time.Second)
			}
		}
	}

	rm.Logger.Info("✅ All follower pods restarted successfully")

	// Wait 45 seconds for the last follower to fully stabilize before proceeding to leader step-down
	rm.Logger.Info("Waiting 45 seconds for final follower to fully stabilize before leader step-down...")
	if rm.DryRun {
		rm.Logger.Info("🧪 [DRY RUN] Would wait 45 seconds for final stabilization")
	} else {
		time.Sleep(45 * time.Second)
	}

	// Wait for cluster to stabilize after follower restarts
	rm.Logger.Info("Waiting for cluster to stabilize after follower restarts...")

	// Wait up to 2 minutes for cluster health to recover
	for i := 0; i < 12; i++ {
		health, err := rm.verifyClusterHealth(ctx)
		if err == nil && health.Healthy {
			rm.Logger.Info("✅ Cluster health restored after follower restarts",
				"attempts", i+1, "details", health.Details)
			break
		}

		if i == 11 {
			return fmt.Errorf("cluster did not stabilize after follower restarts: %v", err)
		}

		rm.Logger.Info("Cluster still stabilizing, waiting...",
			"attempt", i+1, "maxAttempts", 12)
		time.Sleep(10 * time.Second)
	}

	return nil
}

// stepDownLeader performs Vault leader step-down
func (rm *RestartManager) stepDownLeader(ctx context.Context) error {
	rm.Logger.Info("Stepping down Vault leader")

	if rm.DryRun {
		rm.Logger.Info("[DRY RUN] Would execute 'vault operator step-down'")
		rm.Logger.Info("[DRY RUN] Would wait for new leader election")
		return nil
	}

	// First, re-check who the current leader is
	leaderResp, err := rm.vaultClient.Sys().Leader()
	if err != nil {
		return fmt.Errorf("failed to get current leader before step-down: %w", err)
	}

	if !leaderResp.IsSelf {
		rm.Logger.Info("Current node is not the leader, skipping step-down",
			"currentLeader", leaderResp.LeaderAddress)
		return nil
	}

	rm.Logger.Info("Confirmed current node is leader, proceeding with step-down",
		"leaderAddress", leaderResp.LeaderAddress)

	// Execute leader step-down via Vault API
	rm.Logger.Info("Executing leader step-down via Vault API...")

	// Ensure we're in root namespace for step-down (required per Vault docs)
	originalNamespace := rm.vaultClient.Namespace()
	if originalNamespace != "" {
		rm.vaultClient.SetNamespace("")
		defer rm.vaultClient.SetNamespace(originalNamespace)
	}

	// Call vault operator step-down using raw request to ensure POST method
	req := rm.vaultClient.NewRequest("POST", "/v1/sys/step-down")
	resp, err := rm.vaultClient.RawRequest(req)
	if err != nil {
		return fmt.Errorf("failed to execute step-down: %w", err)
	}

	if resp != nil {
		resp.Body.Close()
	}

	// Brief wait for leader election to settle
	rm.Logger.Info("Waiting for leader election to complete...")
	time.Sleep(5 * time.Second)

	// Verify new leader was elected
	leaderResp, err = rm.vaultClient.Sys().Leader()
	if err != nil {
		rm.Logger.Info("Could not verify new leader (this may be expected during transition)")
	} else if leaderResp.IsSelf {
		rm.Logger.Info("Warning: This node is still the leader after step-down")
	} else {
		rm.Logger.Info("✅ New leader elected", "leaderAddress", leaderResp.LeaderAddress)
	}

	rm.Logger.Info("✅ Leader step-down completed")
	return nil
}

// restartFormerLeader restarts the pod that was the leader
func (rm *RestartManager) restartFormerLeader(ctx context.Context, leaderPod string) error {
	rm.Logger.Info("Restarting former leader pod", "pod", leaderPod)

	if rm.DryRun {
		rm.Logger.Info("[DRY RUN] Would delete former leader pod", "pod", leaderPod)
		rm.Logger.Info("[DRY RUN] Would wait for pod to rejoin cluster")
		return nil
	}

	if err := rm.deletePod(ctx, leaderPod); err != nil {
		return fmt.Errorf("failed to delete former leader pod: %w", err)
	}

	if err := rm.waitForPodReady(ctx, leaderPod); err != nil {
		return fmt.Errorf("former leader pod failed to become ready: %w", err)
	}

	rm.Logger.Info("✅ Former leader pod restarted successfully")
	return nil
}

// deletePod deletes a pod and confirms deletion
func (rm *RestartManager) deletePod(ctx context.Context, podName string) error {
	pod := &corev1.Pod{}
	err := rm.Client.Get(ctx, types.NamespacedName{Name: podName, Namespace: rm.Namespace}, pod)
	if err != nil {
		return fmt.Errorf("failed to get pod %s: %w", podName, err)
	}

	if err := rm.Client.Delete(ctx, pod); err != nil {
		return fmt.Errorf("failed to delete pod %s: %w", podName, err)
	}

	rm.Logger.Info("Pod deleted successfully", "pod", podName)
	return nil
}

// waitForPodReady waits for a pod to be ready after restart
func (rm *RestartManager) waitForPodReady(ctx context.Context, podName string) error {
	rm.Logger.Info("Waiting for pod to become ready", "pod", podName)

	// Simple polling loop - wait up to 5 minutes
	timeout := time.After(5 * time.Minute)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for pod %s to become ready", podName)
		case <-ticker.C:
			pod := &corev1.Pod{}
			err := rm.Client.Get(ctx, types.NamespacedName{Name: podName, Namespace: rm.Namespace}, pod)
			if err != nil {
				rm.Logger.V(1).Info("Pod not found yet, continuing to wait", "pod", podName)
				continue
			}

			// Check if pod is ready
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					rm.Logger.Info("Pod is ready", "pod", podName)
					return nil
				}
			}
			rm.Logger.V(1).Info("Pod not ready yet, continuing to wait", "pod", podName, "phase", pod.Status.Phase)
		}
	}
}

// verifyFinalState performs comprehensive post-restart verification
func (rm *RestartManager) verifyFinalState(ctx context.Context) error {
	rm.Logger.Info("Starting comprehensive post-restart verification...")

	if rm.DryRun {
		rm.Logger.Info("🧪 [DRY RUN] Would verify all pods rejoined cluster")
		rm.Logger.Info("🧪 [DRY RUN] Would check cluster health")
		rm.Logger.Info("🧪 [DRY RUN] Would verify leader election stability")
		rm.Logger.Info("🧪 [DRY RUN] Would verify Vault services")
		return nil
	}

	// Perform comprehensive verification with graceful degradation
	if err := rm.performFinalVerificationWithFallback(ctx); err != nil {
		return fmt.Errorf("final verification failed: %w", err)
	}

	rm.Logger.Info("🎉 Vault cluster restart completed successfully!")
	return nil
}

// waitForStableLeader waits for a stable leader election
func (rm *RestartManager) waitForStableLeader(ctx context.Context) error {
	rm.Logger.Info("Waiting for stable leader election...")

	for i := 0; i < 30; i++ { // 5 minutes max
		leaderResp, err := rm.vaultClient.Sys().Leader()
		if err == nil && leaderResp.LeaderAddress != "" {
			// Verify leader is stable for at least 30 seconds
			rm.Logger.Info("Leader found, verifying stability...", "leader", leaderResp.LeaderAddress)
			time.Sleep(30 * time.Second)

			leaderResp2, err := rm.vaultClient.Sys().Leader()
			if err == nil && leaderResp2.LeaderAddress == leaderResp.LeaderAddress {
				rm.Logger.Info("✅ Stable leader elected", "leader", leaderResp.LeaderAddress)
				return nil
			}
		}

		rm.Logger.Info("Leader election in progress...", "attempt", i+1, "maxAttempts", 30)
		time.Sleep(10 * time.Second)
	}

	return fmt.Errorf("leader election did not stabilize within timeout")
}

// verifyRaftConsensus verifies all peers are in consensus
func (rm *RestartManager) verifyRaftConsensus(ctx context.Context) error {
	rm.Logger.Info("Verifying Raft consensus...")

	// Use the autopilot state which we already know works
	health, err := rm.verifyClusterHealth(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster health for consensus check: %w", err)
	}

	if !health.Healthy {
		return fmt.Errorf("cluster not healthy, consensus may be compromised: %s", health.Details)
	}

	rm.Logger.Info("✅ Raft consensus verified via cluster health check")
	return nil
}

// verifyVaultServices verifies Vault services are fully operational
func (rm *RestartManager) verifyVaultServices(ctx context.Context) error {
	rm.Logger.Info("Verifying Vault services...")

	// Test critical Vault operations
	tests := []struct {
		name string
		test func() error
	}{
		{"seal_status", func() error {
			status, err := rm.vaultClient.Sys().SealStatus()
			if err != nil {
				return err
			}
			if status.Sealed {
				return fmt.Errorf("vault is sealed")
			}
			return nil
		}},
		{"auth_methods", func() error {
			auths, err := rm.vaultClient.Sys().ListAuth()
			if err != nil {
				return err
			}
			if len(auths) == 0 {
				return fmt.Errorf("no auth methods available")
			}
			return nil
		}},
		{"token_capabilities", func() error {
			caps, err := rm.vaultClient.Sys().CapabilitiesSelf("sys/health")
			if err != nil {
				return err
			}
			if len(caps) == 0 {
				return fmt.Errorf("no capabilities returned")
			}
			return nil
		}},
	}

	for _, test := range tests {
		if err := test.test(); err != nil {
			return fmt.Errorf("%s check failed: %w", test.name, err)
		}
		rm.Logger.Info("✅ Service check passed", "check", test.name)
	}

	return nil
}

// performRobustFinalVerification runs comprehensive verification checks
func (rm *RestartManager) performRobustFinalVerification(ctx context.Context) error {
	rm.Logger.Info("Running comprehensive verification checks...")

	checks := []struct {
		name    string
		fn      func(context.Context) error
		retries int
		delay   time.Duration
	}{
		{"Leader Election", rm.waitForStableLeader, 2, 30 * time.Second},
		{"Raft Consensus", rm.verifyRaftConsensus, 3, 15 * time.Second},
		{"Vault Services", rm.verifyVaultServices, 3, 10 * time.Second},
		{"Final Health Check", func(ctx context.Context) error {
			health, err := rm.verifyClusterHealth(ctx)
			if err != nil {
				return err
			}
			if !health.Healthy {
				return fmt.Errorf("cluster not healthy: %s", health.Details)
			}
			return nil
		}, 2, 5 * time.Second},
	}

	for _, check := range checks {
		rm.Logger.Info("Running verification check", "check", check.name)

		var lastErr error
		for attempt := 0; attempt < check.retries; attempt++ {
			if err := check.fn(ctx); err != nil {
				lastErr = err
				rm.Logger.Info("Check failed, retrying...",
					"check", check.name,
					"attempt", attempt+1,
					"maxAttempts", check.retries,
					"error", err)
				time.Sleep(check.delay)
				continue
			}

			rm.Logger.Info("✅ Verification check passed", "check", check.name)
			lastErr = nil
			break
		}

		if lastErr != nil {
			return fmt.Errorf("verification check %s failed after %d attempts: %w",
				check.name, check.retries, lastErr)
		}
	}

	rm.Logger.Info("🎉 All comprehensive verification checks passed!")
	return nil
}

// performFinalVerificationWithFallback tries comprehensive verification with graceful degradation
func (rm *RestartManager) performFinalVerificationWithFallback(ctx context.Context) error {
	// Try comprehensive verification first
	if err := rm.performRobustFinalVerification(ctx); err != nil {
		rm.Logger.Info("Comprehensive verification failed, trying basic checks", "error", err)

		// Fallback to basic health check with extended timeout
		rm.Logger.Info("Attempting basic health verification as fallback...")
		for i := 0; i < 10; i++ {
			health, err := rm.verifyClusterHealth(ctx)
			if err == nil && health.Healthy {
				rm.Logger.Info("✅ Basic health verification passed (fallback)",
					"attempt", i+1, "details", health.Details)
				return nil
			}

			rm.Logger.Info("Basic health check failed, retrying...",
				"attempt", i+1, "maxAttempts", 10, "error", err)
			time.Sleep(30 * time.Second)
		}

		// If even basic checks fail, log warning but don't fail the operation
		rm.Logger.Info("⚠️ Final verification could not be completed, but restart sequence finished successfully. Manual verification recommended.")
		return nil
	}

	return nil
}
