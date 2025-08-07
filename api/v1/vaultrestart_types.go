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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultRestartSpec defines the desired state of VaultRestart.
type VaultRestartSpec struct {
	// SecretName is the name of the Secret to watch for certificate changes
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`

	// StatefulSetName specifies the name of the Vault StatefulSet to restart
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	StatefulSetName string `json:"statefulSetName"`

	// Reason specifies why the restart is being performed
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=baseline;cert-rotation;config-change;maintenance;manual
	Reason string `json:"reason"`
}

// VaultRestartStatus defines the observed state of VaultRestart.
type VaultRestartStatus struct {
	// Phase represents the current phase of the restart operation
	// +kubebuilder:validation:Enum=Pending;WaitingForCertPropagation;Validating;InProgress;Completed;Failed
	Phase string `json:"phase,omitempty"`

	// Message provides human-readable information about the current state
	Message string `json:"message,omitempty"`

	// LastUpdated is the timestamp of the last status update
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// SecretHash is the hash of the secret content when this restart was triggered
	// This is automatically populated by the operator
	SecretHash string `json:"secretHash,omitempty"`

	// StartTime is when the restart operation began
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the restart operation completed
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// StatefulSetName is the name of the StatefulSet being restarted
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Namespaced,shortName=vr
//+kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
//+kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".spec.reason"
//+kubebuilder:printcolumn:name="StatefulSet",type="string",JSONPath=".spec.statefulSetName"
//+kubebuilder:printcolumn:name="Secret",type="string",JSONPath=".spec.secretName"
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// VaultRestart is the Schema for the vaultrestarts API
type VaultRestart struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultRestartSpec   `json:"spec,omitempty"`
	Status VaultRestartStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultRestartList contains a list of VaultRestart.
type VaultRestartList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultRestart `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultRestart{}, &VaultRestartList{})
}
