/*
Copyright 2023 IPA CyberLab.

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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DistinguishedName struct {
	CommonName         string `json:"commonName,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	Country            string `json:"country,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"streetAddress,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
}

// KmgmKeyType represents a public key algorithm used to sign the certificate.
// +kubebuilder:validation:Enum=unspecified;rsa4096;secp256r1;rsa2048
type KmgmKeyType string

const (
	KmgmKeyTypeUnspecified KmgmKeyType = "unspecified"
	KmgmKeyTypeRSA4096     KmgmKeyType = "rsa4096"
	KmgmKeyTypeSECP256R1   KmgmKeyType = "secp256r1"
	KmgmKeyTypeRSA2048     KmgmKeyType = "rsa2048"
)

// KmgmProfileSpec defines the desired state of KmgmProfile
type KmgmProfileSpec struct {
	// KmgmName is the name of Kmgm that the profile should be created on
	KmgmName string `json:"kmgmName,omitempty"`

	// Subject is a X509 distinguished name to be assigned to the CA certificate.
	Subject *DistinguishedName `json:"subject,omitempty"`

	// KmgmKeyType specifies the public key algorithm the CA private key should use.
	KmgmKeyType KmgmKeyType `json:"keyType,omitempty"`

	// Validity specifies the duration the CA certificate should be valid for.
	Validity *metav1.Duration `json:"notAfter,omitempty"`
}

// +kubebuilder:validation:Enum=Ready;CASetup
type KmgmProfileConditionType string

const (
	KmgmProfileConditionReady   KmgmProfileConditionType = "Ready"
	KmgmProfileConditionCASetup KmgmProfileConditionType = "CASetup"
)

// KmgmProfileCondition contains condition information for an KmgmProfile.
type KmgmProfileCondition struct {
	Type KmgmProfileConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// KmgmProfileStatus defines the observed state of KmgmProfile
type KmgmProfileStatus struct {
	Conditions []KmgmProfileCondition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// KmgmProfile is the schema for the kmgm API, where each kmgm
type KmgmProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KmgmProfileSpec   `json:"spec,omitempty"`
	Status KmgmProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KmgmProfileList contains a list of KmgmProfile
type KmgmProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KmgmProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KmgmProfile{}, &KmgmProfileList{})
}
