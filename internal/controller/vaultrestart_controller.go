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

package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	vaultv1 "github.com/app-sre/vault-restart-operator/api/v1"
	"github.com/app-sre/vault-restart-operator/internal/vault"
	vaultapi "github.com/hashicorp/vault/api"
	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// VaultRestartReconciler reconciles a VaultRestart object
type VaultRestartReconciler struct {
	client.Client
	VaultClient *vaultapi.Client
	Scheme      *runtime.Scheme
}

//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;delete
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch
// +kubebuilder:rbac:groups=vault.appsre.redhat.com,resources=vaultrestarts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.appsre.redhat.com,resources=vaultrestarts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.appsre.redhat.com,resources=vaultrestarts/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *VaultRestartReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the VaultRestart instance
	vr := &vaultv1.VaultRestart{}
	if err := r.Get(ctx, req.NamespacedName, vr); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("VaultRestart resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get VaultRestart")
		return ctrl.Result{}, err
	}

	// If this is the first reconciliation, populate the secret hash
	if vr.Status.SecretHash == "" {
		return r.initializeVaultRestart(ctx, vr)
	}

	// State machine based on current phase
	switch vr.Status.Phase {
	case "", "Pending":
		return r.handlePendingPhase(ctx, vr)
	case "WaitingForCertPropagation":
		return r.handleCertPropagationWait(ctx, vr)
	case "Validating":
		return r.handleClusterValidation(ctx, vr)
	case "InProgress":
		return r.handleRestartExecution(ctx, vr)
	case "Completed", "Failed":
		return ctrl.Result{}, nil
	default:
		return ctrl.Result{}, fmt.Errorf("unknown phase: %s", vr.Status.Phase)
	}
}

// SetupWithManager is a method used within a controller to
// register the controller with a controller-runtime Manager
func (r *VaultRestartReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// No automatic baseline initialization - users must create VaultRestart CRs with proper configuration

	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1.VaultRestart{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1, // Ensure serial processing
		}).
		// Watch Secrets with vault.operator/watch label
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.handleSecretChange),
			builder.WithPredicates(r.vaultSecretPredicate()),
		).
		// Watch Routes to detect cert-utils-operator updates
		Watches(
			&routev1.Route{},
			handler.EnqueueRequestsFromMapFunc(r.handleRouteChange),
			builder.WithPredicates(r.vaultRoutePredicate()),
		).
		Complete(r)
}

// Predicate to filter only watched vault secrets
func (r *VaultRestartReconciler) vaultSecretPredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return false
		}
		return secret.GetLabels()["vault.operator/watch"] == "true"
	})
}

// Predicate to filter only vault routes
func (r *VaultRestartReconciler) vaultRoutePredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		route, ok := obj.(*routev1.Route)
		if !ok {
			return false
		}
		return route.GetLabels()["app.kubernetes.io/name"] == "vault"
	})
}

// Handle secret changes - auto-create VaultRestart CRs
func (r *VaultRestartReconciler) handleSecretChange(ctx context.Context, obj client.Object) []ctrl.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return []ctrl.Request{}
	}

	// Find which StatefulSet uses this Secret
	statefulSetName, err := r.findStatefulSetUsingSecret(ctx, secret.GetName(), secret.GetNamespace())
	if err != nil {
		return nil
	}

	// Get the full Secret object and calculate hash
	secretObj := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      secret.GetName(),
		Namespace: secret.GetNamespace(),
	}, secretObj)
	if err != nil {
		return nil
	}

	currentHash := r.calculateSecretHash(secretObj)

	// Skip auto-restart creation for newly labeled secrets without existing baselines
	// Users must create an initial VaultRestart CR with proper configuration
	if !r.hasBaselineForSecret(ctx, secret.GetName(), secret.GetNamespace()) {
		logger := log.FromContext(ctx)
		logger.Info("Newly labeled secret discovered, but no VaultRestart baseline exists. Create a VaultRestart CR with proper Vault configuration to enable auto-restarts",
			"secret", secret.GetName(), "namespace", secret.GetNamespace())
		return nil // Don't create anything automatically
	}

	// Check for existing restart with same hash
	if r.hasExistingRestartForHash(ctx, secret.GetNamespace(), secret.GetName(), currentHash) {
		return nil
	}

	// Get Vault configuration from an existing VaultRestart CR for this secret
	vaultConfig, err := r.getVaultConfigForSecret(ctx, secret.GetName(), secret.GetNamespace())
	if err != nil {
		logger := log.FromContext(ctx)
		logger.Info("Could not get Vault configuration for auto-restart", "secret", secret.GetName(), "error", err)
		return nil
	}

	// Create VaultRestart CR for actual change
	vr := &vaultv1.VaultRestart{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("auto-restart-%s-%d", secret.GetName(), time.Now().Unix()),
			Namespace: secret.GetNamespace(),
			Labels: map[string]string{
				"vault.operator/trigger": "auto",
				"vault.operator/secret":  secret.GetName(),
			},
		},
		Spec: vaultv1.VaultRestartSpec{
			StatefulSetName: statefulSetName,
			SecretName:      secret.GetName(),
			Reason:          "cert-rotation",
			VaultAddress:    vaultConfig.VaultAddress,
			VaultRole:       vaultConfig.VaultRole,
			DryRun:          vaultConfig.DryRun,
		},
	}

	if err := r.Create(ctx, vr); err != nil {
		return nil
	}

	return []ctrl.Request{{
		NamespacedName: types.NamespacedName{
			Name:      vr.Name,
			Namespace: vr.Namespace,
		},
	}}
}

// Handle route changes - trigger reconciliation for waiting VaultRestarts
func (r *VaultRestartReconciler) handleRouteChange(ctx context.Context, obj client.Object) []ctrl.Request {
	route, ok := obj.(*routev1.Route)
	if !ok {
		return []ctrl.Request{}
	}

	// Find VaultRestart CRs in "WaitingForCertPropagation" phase
	vaultRestarts := &vaultv1.VaultRestartList{}
	err := r.List(ctx, vaultRestarts, &client.ListOptions{
		Namespace: route.GetNamespace(),
	})
	if err != nil {
		return nil
	}

	var requests []ctrl.Request
	for _, vr := range vaultRestarts.Items {
		if vr.Status.Phase == "WaitingForCertPropagation" {
			requests = append(requests, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      vr.Name,
					Namespace: vr.Namespace,
				},
			})
		}
	}

	return requests
}

// Initialize VaultRestart with secret hash
func (r *VaultRestartReconciler) initializeVaultRestart(ctx context.Context, vr *vaultv1.VaultRestart) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Get the secret and calculate its hash
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      vr.Spec.SecretName,
		Namespace: vr.Namespace,
	}, secret)
	if err != nil {
		logger.Error(err, "Failed to get secret", "secret", vr.Spec.SecretName)
		return ctrl.Result{}, err
	}

	// Calculate and store the hash
	vr.Status.SecretHash = r.calculateSecretHash(secret)
	vr.Status.Phase = "Pending"
	vr.Status.Message = "VaultRestart initialized, preparing for execution"
	vr.Status.LastUpdated = &metav1.Time{Time: time.Now()}
	vr.Status.ObservedGeneration = vr.Generation

	if err := r.Status().Update(ctx, vr); err != nil {
		logger.Error(err, "Failed to update VaultRestart status")
		return ctrl.Result{}, err
	}

	logger.Info("Initialized VaultRestart", "name", vr.Name, "secretHash", vr.Status.SecretHash)
	return ctrl.Result{Requeue: true}, nil
}

// Handle pending phase - start the restart process
func (r *VaultRestartReconciler) handlePendingPhase(ctx context.Context, vr *vaultv1.VaultRestart) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	vr.Status.Phase = "WaitingForCertPropagation"
	vr.Status.Message = "Waiting for cert-utils-operator to propagate certificate changes"
	vr.Status.StartTime = &metav1.Time{Time: time.Now()}
	vr.Status.LastUpdated = &metav1.Time{Time: time.Now()}

	if err := r.Status().Update(ctx, vr); err != nil {
		logger.Error(err, "Failed to update VaultRestart status")
		return ctrl.Result{}, err
	}

	logger.Info("VaultRestart moved to WaitingForCertPropagation phase", "name", vr.Name)
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// Handle cert propagation wait
func (r *VaultRestartReconciler) handleCertPropagationWait(ctx context.Context, vr *vaultv1.VaultRestart) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// check if route certificates match secret certificates
	if err := r.validateCertUtilsOperatorComplete(ctx, vr); err != nil {
		vr.Status.Message = fmt.Sprintf("Waiting for cert-utils-operator: %v", err)
		vr.Status.LastUpdated = &metav1.Time{Time: time.Now()}
		r.Status().Update(ctx, vr)

		logger.Info("cert-utils-operator validation failed, continuing to wait",
			"name", vr.Name, "error", err.Error())

		// Requeue after 30 seconds to check again
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Add a brief grace period after validation passes
	gracePeriod := 1 * time.Minute
	if time.Since(vr.Status.StartTime.Time) < gracePeriod {
		remainingTime := gracePeriod - time.Since(vr.Status.StartTime.Time)
		vr.Status.Message = fmt.Sprintf("Certificate propagation complete, grace period: %v remaining",
			remainingTime.Round(time.Second))
		vr.Status.LastUpdated = &metav1.Time{Time: time.Now()}
		r.Status().Update(ctx, vr)

		return ctrl.Result{RequeueAfter: remainingTime}, nil
	}

	// All checks passed, proceed to cluster validation
	vr.Status.Phase = "Validating"
	vr.Status.Message = "Certificate propagation complete, validating Vault cluster health"
	vr.Status.LastUpdated = &metav1.Time{Time: time.Now()}

	if err := r.Status().Update(ctx, vr); err != nil {
		logger.Error(err, "Failed to update VaultRestart status")
		return ctrl.Result{}, err
	}

	logger.Info("Certificate propagation complete, moving to cluster validation", "name", vr.Name)
	return ctrl.Result{Requeue: true}, nil
}

// Handle cluster validation
func (r *VaultRestartReconciler) handleClusterValidation(ctx context.Context, vr *vaultv1.VaultRestart) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	namespacedName := types.NamespacedName{Name: vr.Name, Namespace: vr.Namespace}

	// Validate Vault cluster health
	if err := r.validateVaultClusterHealth(ctx, vr); err != nil {
		// Update status to Failed using safe update
		updateErr := r.updateVaultRestartStatus(ctx, namespacedName, func(vr *vaultv1.VaultRestart) {
			vr.Status.Phase = "Failed"
			vr.Status.Message = fmt.Sprintf("Cluster health validation failed: %v", err)
			vr.Status.CompletionTime = &metav1.Time{Time: time.Now()}
			vr.Status.LastUpdated = &metav1.Time{Time: time.Now()}
		})

		if updateErr != nil {
			logger.Error(updateErr, "Failed to update status to Failed")
		}

		logger.Error(err, "Cluster health validation failed", "name", vr.Name)
		return ctrl.Result{}, nil
	}

	// Move to execution phase using safe update
	if err := r.updateVaultRestartStatus(ctx, namespacedName, func(vr *vaultv1.VaultRestart) {
		vr.Status.Phase = "InProgress"
		vr.Status.Message = "Cluster validation passed, starting controlled restart sequence"
		vr.Status.LastUpdated = &metav1.Time{Time: time.Now()}
	}); err != nil {
		logger.Error(err, "Failed to update VaultRestart status")
		return ctrl.Result{}, err
	}

	logger.Info("VaultRestart moved to InProgress phase", "name", vr.Name)
	return ctrl.Result{Requeue: true}, nil
}

// Handle restart execution
func (r *VaultRestartReconciler) handleRestartExecution(ctx context.Context, vr *vaultv1.VaultRestart) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	namespacedName := types.NamespacedName{Name: vr.Name, Namespace: vr.Namespace}

	// Execute the controlled restart sequence
	if err := r.executeVaultRestart(ctx, vr); err != nil {
		// Update status to Failed using safe update
		updateErr := r.updateVaultRestartStatus(ctx, namespacedName, func(vr *vaultv1.VaultRestart) {
			vr.Status.Phase = "Failed"
			vr.Status.Message = fmt.Sprintf("Restart execution failed: %v", err)
			vr.Status.CompletionTime = &metav1.Time{Time: time.Now()}
			vr.Status.LastUpdated = &metav1.Time{Time: time.Now()}
		})

		if updateErr != nil {
			logger.Error(updateErr, "Failed to update status to Failed")
		}

		logger.Error(err, "Restart execution failed", "name", vr.Name)
		return ctrl.Result{}, err
	}

	// Mark as completed using safe update
	if err := r.updateVaultRestartStatus(ctx, namespacedName, func(vr *vaultv1.VaultRestart) {
		vr.Status.Phase = "Completed"
		vr.Status.Message = "Vault cluster restart completed successfully"
		vr.Status.CompletionTime = &metav1.Time{Time: time.Now()}
		vr.Status.LastUpdated = &metav1.Time{Time: time.Now()}
	}); err != nil {
		logger.Error(err, "Failed to update VaultRestart status")
		return ctrl.Result{}, err
	}

	logger.Info("VaultRestart completed successfully", "name", vr.Name)
	return ctrl.Result{}, nil
}

// validate certificate content in cert-utils-operator
func (r *VaultRestartReconciler) validateCertUtilsOperatorComplete(ctx context.Context, vr *vaultv1.VaultRestart) error {
	logger := log.FromContext(ctx)

	// Get current certificate from secret
	certSecret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      vr.Spec.SecretName,
		Namespace: vr.Namespace,
	}, certSecret)
	if err != nil {
		return fmt.Errorf("failed to get certificate secret: %w", err)
	}

	currentCACert := string(certSecret.Data["ca.crt"])

	// Get all vault routes
	routes := &routev1.RouteList{}
	err = r.List(ctx, routes, &client.ListOptions{
		Namespace: vr.Namespace,
	}, client.MatchingLabels{"app.kubernetes.io/name": "vault"})
	if err != nil {
		return fmt.Errorf("failed to list vault routes: %w", err)
	}

	if len(routes.Items) == 0 {
		logger.Info("No vault routes found, skipping route validation")
		return nil
	}

	// Check each route's destinationCACertificate
	for _, route := range routes.Items {
		if route.Spec.TLS == nil {
			logger.Info("Skipping non-TLS route", "route", route.Name)
			continue
		}

		// Does the Route's CA match the Secret's CA?
		if route.Spec.TLS.DestinationCACertificate != currentCACert {
			return fmt.Errorf("route %s destinationCACertificate not yet updated", route.Name)
		}

		logger.Info("Route validation passed", "route", route.Name)
	}

	logger.Info("All routes have updated destinationCACertificate", "routeCount", len(routes.Items))
	return nil
}

// Find StatefulSet that uses the given secret
func (r *VaultRestartReconciler) findStatefulSetUsingSecret(ctx context.Context, secretName, namespace string) (string, error) {
	statefulSets := &appsv1.StatefulSetList{}
	err := r.List(ctx, statefulSets, &client.ListOptions{
		Namespace: namespace,
	})
	if err != nil {
		return "", err
	}

	for _, sts := range statefulSets.Items {
		for _, volume := range sts.Spec.Template.Spec.Volumes {
			if volume.Secret != nil && volume.Secret.SecretName == secretName {
				return sts.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no StatefulSet found that mounts secret %s", secretName)
}

// Check if restart already exists for this secret hash
func (r *VaultRestartReconciler) hasExistingRestartForHash(ctx context.Context, namespace, secretName, hash string) bool {
	existingVR := &vaultv1.VaultRestartList{}
	err := r.List(ctx, existingVR, &client.ListOptions{
		Namespace: namespace,
	})
	if err != nil {
		return false
	}

	for _, vr := range existingVR.Items {
		if vr.Status.SecretHash == hash && vr.Spec.SecretName == secretName {
			return true
		}
	}

	return false
}

// Calculate hash of secret content
func (r *VaultRestartReconciler) calculateSecretHash(secret *corev1.Secret) string {
	hasher := sha256.New()

	if cert, exists := secret.Data["tls.crt"]; exists {
		hasher.Write(cert)
	}
	if key, exists := secret.Data["tls.key"]; exists {
		hasher.Write(key)
	}
	if ca, exists := secret.Data["ca.crt"]; exists {
		hasher.Write(ca)
	}

	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// Validate Vault cluster health (simplified version)
func (r *VaultRestartReconciler) validateVaultClusterHealth(ctx context.Context, vr *vaultv1.VaultRestart) error {
	logger := log.FromContext(ctx)

	// Get Vault pods
	pods := &corev1.PodList{}
	err := r.List(ctx, pods, &client.ListOptions{
		Namespace: vr.Namespace,
	}, client.MatchingLabels{"app.kubernetes.io/name": "vault"})
	if err != nil {
		return fmt.Errorf("failed to list vault pods: %w", err)
	}

	// Basic health checks
	readyPods := 0
	totalPods := len(pods.Items)

	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					readyPods++
					break
				}
			}
		}
	}

	logger.Info("Vault cluster health check", "readyPods", readyPods, "totalPods", totalPods)

	// Require at least 2 ready pods for restart (quorum)
	if readyPods < 2 {
		return fmt.Errorf("insufficient ready pods for safe restart: %d/%d (need at least 2)", readyPods, totalPods)
	}

	logger.Info("Vault cluster health validation passed", "readyPods", readyPods, "totalPods", totalPods)
	return nil
}

// Execute controlled Vault restart sequence
func (r *VaultRestartReconciler) executeVaultRestart(ctx context.Context, vr *vaultv1.VaultRestart) error {
	logger := log.FromContext(ctx)

	// Get configuration from VaultRestart CR spec
	vaultAddress := vr.Spec.VaultAddress
	vaultRole := vr.Spec.VaultRole
	dryRun := vr.Spec.DryRun

	logger.Info("Configuring Vault restart manager",
		"vaultAddress", vaultAddress,
		"vaultRole", vaultRole,
		"dryRun", dryRun)

	// Create RestartManager with configuration from CR
	restartManager := &vault.RestartManager{
		Client:       r.Client,
		VaultAddress: vaultAddress,
		VaultRole:    vaultRole,
		Namespace:    vr.Namespace,
		Logger:       logger,
		DryRun:       dryRun,
	}

	// Execute the restart sequence
	return restartManager.ExecuteRestart(ctx, vr.Spec.StatefulSetName)
}

// hasBaselineForSecret checks if any VaultRestart CR exists for the given secret
func (r *VaultRestartReconciler) hasBaselineForSecret(ctx context.Context, secretName, namespace string) bool {
	vaultRestarts := &vaultv1.VaultRestartList{}
	err := r.List(ctx, vaultRestarts, &client.ListOptions{
		Namespace: namespace,
	})
	if err != nil {
		return false
	}

	for _, vr := range vaultRestarts.Items {
		// Check if this is a restart for the same secret
		if vr.Spec.SecretName == secretName {
			return true
		}
	}

	return false
}

// VaultConfig holds Vault connection configuration
type VaultConfig struct {
	VaultAddress string
	VaultRole    string
	DryRun       bool
}

// getVaultConfigForSecret retrieves Vault configuration from an existing VaultRestart CR for the given secret
func (r *VaultRestartReconciler) getVaultConfigForSecret(ctx context.Context, secretName, namespace string) (*VaultConfig, error) {
	vaultRestarts := &vaultv1.VaultRestartList{}
	err := r.List(ctx, vaultRestarts, &client.ListOptions{
		Namespace: namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list VaultRestart CRs: %w", err)
	}

	// Find the most recent VaultRestart CR for this secret
	var latestVR *vaultv1.VaultRestart
	for _, vr := range vaultRestarts.Items {
		if vr.Spec.SecretName == secretName {
			if latestVR == nil || vr.CreationTimestamp.After(latestVR.CreationTimestamp.Time) {
				vrCopy := vr
				latestVR = &vrCopy
			}
		}
	}

	if latestVR == nil {
		return nil, fmt.Errorf("no VaultRestart CR found for secret %s", secretName)
	}

	return &VaultConfig{
		VaultAddress: latestVR.Spec.VaultAddress,
		VaultRole:    latestVR.Spec.VaultRole,
		DryRun:       latestVR.Spec.DryRun,
	}, nil
}

// updateVaultRestartStatus safely updates the VaultRestart status with retry logic
func (r *VaultRestartReconciler) updateVaultRestartStatus(ctx context.Context, namespacedName types.NamespacedName, updateFunc func(*vaultv1.VaultRestart)) error {
	// Retry up to 3 times with exponential backoff
	for i := 0; i < 3; i++ {
		// Fetch the latest version of the VaultRestart
		vr := &vaultv1.VaultRestart{}
		if err := r.Get(ctx, namespacedName, vr); err != nil {
			return err
		}

		// Apply the update function
		updateFunc(vr)

		// Attempt to update the status
		if err := r.Status().Update(ctx, vr); err != nil {
			if i < 2 { // Only retry if we haven't reached the max attempts
				time.Sleep(time.Duration(i+1) * 100 * time.Millisecond) // Exponential backoff
				continue
			}
			return err
		}

		// Success
		return nil
	}

	return fmt.Errorf("failed to update status after retries")
}
