#!/bin/bash
set -euo pipefail

go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.11
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
