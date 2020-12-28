module github.com/IPA-CyberLab/kmgm-issuer

go 1.15

require (
	github.com/IPA-CyberLab/kmgm v0.2.3
	github.com/go-logr/logr v0.3.0
	github.com/go-logr/zapr v0.3.0
	github.com/google/go-cmp v0.5.4
	github.com/jetstack/cert-manager v1.1.0
	github.com/prometheus/common v0.15.0
	go.uber.org/multierr v1.6.0
	go.uber.org/zap v1.16.0
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1
	sigs.k8s.io/controller-runtime v0.6.4
)

// replace github.com/IPA-CyberLab/kmgm => ../kmgm
