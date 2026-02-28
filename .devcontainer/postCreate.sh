#!/bin/bash
set -euo pipefail

go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest
go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
