package main

import (
	"github.com/aquasecurity/kubectl-who-can/pkg/cmd"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"os"
)

func main() {
	root := cmd.NewCmdWhoCan()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
