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

// KmgmSpec defines the desired state of Kmgm
type KmgmSpec struct {
	// Kmgm container image to be deployed to the pods.
	Image string `json:"image,omitempty"`

	// KmgmProfiles to be selected to be assigned to this Kmgm insntance.
	KmgmProfileSelector *metav1.LabelSelector `json:"kmgmProfileSelector,omitempty"`
}

// +kubebuilder:validation:Enum=Ready
type KmgmConditionType string

const (
	KmgmConditionReady KmgmConditionType = "Ready"
)

// KmgmCondition contains condition information for an Kmgm.
type KmgmCondition struct {
	Type KmgmConditionType `json:"type"`

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

// KmgmStatus defines the observed state of Kmgm
type KmgmStatus struct {
	Conditions []KmgmCondition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Kmgm is the schema for the kmgm API, where each kmgm
type Kmgm struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KmgmSpec   `json:"spec,omitempty"`
	Status KmgmStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KmgmList contains a list of Kmgm
type KmgmList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Kmgm `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Kmgm{}, &KmgmList{})
}
