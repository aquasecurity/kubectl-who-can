package main

import (
	"fmt"
	"github.com/aquasecurity/kubectl-who-can/pkg/cmd"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	// Load all known auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"os"
)

func main() {
	root, err := cmd.NewCmdWhoCan(clioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
