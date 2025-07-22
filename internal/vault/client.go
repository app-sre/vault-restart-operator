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

	vaultapi "github.com/hashicorp/vault/api"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// LoginWithKubernetesAuth authenticates to Vault using the Kubernetes auth method
func LoginWithKubernetesAuth(ctx context.Context, vaultAddr, role string) (*vaultapi.Client, error) {
	logger := log.FromContext(ctx)

	config := vaultapi.DefaultConfig()
	config.Address = vaultAddr

	// Configure TLS if needed
	config.ConfigureTLS(&vaultapi.TLSConfig{
		// Set based on environment
		Insecure: false,
	})

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Get the JWT token from the Kubernetes service account
	jwt, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token: %w", err)
	}

	data := map[string]interface{}{
		"role": role,
		"jwt":  string(jwt),
	}

	secret, err := client.Logical().Write("auth/kubernetes/login", data)
	if err != nil {
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
