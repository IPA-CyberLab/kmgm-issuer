package main

//go:generate controller-gen crd paths="./..." output:crd:artifacts:config=charts/kmgm-issuer/controller-gen/crd
//go:generate sh -c "controller-gen rbac:roleName=manager-role paths=\"./...\" output:stdout > charts/kmgm-issuer/controller-gen/role.yaml"
//go:generate controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."
