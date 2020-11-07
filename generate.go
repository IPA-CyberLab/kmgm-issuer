package main

//go:generate controller-gen crd:trivialVersions=true rbac:roleName=manager-role paths="./..." output:crd:artifacts:config=config/crd
//go:generate controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."
