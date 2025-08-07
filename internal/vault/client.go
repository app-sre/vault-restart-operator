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
	"os"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// LoginWithKubernetesAuth authenticates to Vault using the Kubernetes auth method
func LoginWithKubernetesAuth(ctx context.Context, vaultAddr, role string) (*vaultapi.Client, error) {
	// Use the default service account token (the one the pod is running with)
	return LoginWithKubernetesAuthAndToken(ctx, vaultAddr, role, "")
}

// LoginWithKubernetesAuthAndServiceAccount authenticates to Vault using a specific service account
func LoginWithKubernetesAuthAndServiceAccount(ctx context.Context, k8sClient client.Client, vaultAddr, role, serviceAccountName, namespace string) (*vaultapi.Client, error) {
	logger := log.FromContext(ctx)

	// Get the service account token from Kubernetes
	logger.Info("Getting service account token", "serviceAccount", serviceAccountName, "namespace", namespace)
	
	sa := &corev1.ServiceAccount{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: serviceAccountName, Namespace: namespace}, sa)
	if err != nil {
		return nil, fmt.Errorf("failed to get service account %s/%s: %w", namespace, serviceAccountName, err)
	}

	// Use TokenRequest API to create a short-lived token for the service account
	logger.Info("Requesting token for service account using TokenRequest API")
	
	// Create a TokenRequest for 1 hour expiration
	expirationSeconds := int64(3600) // 1 hour
	tokenRequest := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: &expirationSeconds,
		},
	}

	// Use the SubResource method to create the token
	err = k8sClient.SubResource("token").Create(ctx, sa, tokenRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create token for service account %s/%s: %w", namespace, serviceAccountName, err)
	}

	if tokenRequest.Status.Token == "" {
		return nil, fmt.Errorf("empty token returned for service account %s/%s", namespace, serviceAccountName)
	}

	logger.Info("Successfully created token for service account", 
		"serviceAccount", serviceAccountName, 
		"namespace", namespace,
		"tokenLength", len(tokenRequest.Status.Token),
		"expiresAt", tokenRequest.Status.ExpirationTimestamp.Time)

	return LoginWithKubernetesAuthAndToken(ctx, vaultAddr, role, tokenRequest.Status.Token)
}

// LoginWithKubernetesAuthAndToken authenticates to Vault using a specific JWT token
func LoginWithKubernetesAuthAndToken(ctx context.Context, vaultAddr, role, jwtToken string) (*vaultapi.Client, error) {
	logger := log.FromContext(ctx)

	logger.Info("Creating Vault client", "address", vaultAddr)
	config := vaultapi.DefaultConfig()
	config.Address = vaultAddr
	config.Timeout = 30 * time.Second

	// Configure TLS if needed
	config.ConfigureTLS(&vaultapi.TLSConfig{
		// Set based on environment
		Insecure: false,
	})

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	var jwt []byte
	
	if jwtToken == "" {
		logger.Info("Reading default service account token")
		// Get the JWT token from the default Kubernetes service account
		jwt, err = os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			return nil, fmt.Errorf("failed to read service account token: %w", err)
		}
	} else {
		logger.Info("Using provided JWT token")
		jwt = []byte(jwtToken)
	}

	logger.Info("Attempting Vault login", "role", role, "jwtLength", len(jwt))
	data := map[string]interface{}{
		"role": role,
		"jwt":  string(jwt),
	}

	secret, err := client.Logical().Write("auth/kubernetes/login", data)
	if err != nil {
		logger.Error(err, "Vault login failed", "address", vaultAddr, "role", role)
		return nil, fmt.Errorf("vault k8s login failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("no auth info returned after login")
	}

	client.SetToken(secret.Auth.ClientToken)

	logger.Info("Successfully authenticated with Vault",
		"address", vaultAddr,
		"role", role,
		"policies", secret.Auth.Policies,
		"ttl", secret.Auth.LeaseDuration)

	return client, nil
}
