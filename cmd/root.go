package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	// "k8s.io/cli-runtime/pkg/genericclioptions"
)

type role struct {
	name          string
	isClusterRole bool
}

type roles map[role]struct{}

type whoCan struct {
	verb         string
	resource     string
	resourceName string
	client       kubernetes.Interface
	r            roles
}

// RootCmd is the command we're goimg to run
var RootCmd = &cobra.Command{
	Use:     "kubectl-who-can VERB TYPE",
	Short:   "who-can shows which users, groups and service accounts can perform a given action",
	Long:    "who-can shows which users, groups and service accounts can perform a given verb on a given resource type",
	Example: "TBC",
	Run: func(cmd *cobra.Command, args []string) {
		w := whoCan{}
		if err := w.Complete(args); err != nil {
			fmt.Printf("Incomplete command: %v\n", err)
		}
		if err := cmd.ParseFlags(args); err != nil {
			fmt.Printf("Error parsing flags: %v\n", err)
		}

		clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		)

		kubeconfig, err := clientConfig.ClientConfig()
		if err != nil {
			fmt.Printf("Error getting config: %v\n", err)
			os.Exit(1)
		}

		w.client, err = kubernetes.NewForConfig(kubeconfig)
		if err != nil {
			fmt.Printf("Error creating client: %v\n", err)
			os.Exit(1)
		}

		if err := w.do(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	flag.CommandLine.VisitAll(func(goflag *flag.Flag) {
		RootCmd.PersistentFlags().AddGoFlag(goflag)
	})
}

// Execute is the primary entrypoint for this CLI
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func (w *whoCan) Complete(args []string) error {
	switch len(args) {
	case 2, 3:
		w.verb = args[0]
		w.resource = args[1]
		if len(args) == 3 {
			w.resourceName = args[2]
			fmt.Println("Resource name checking not yet implemented")
		}
	default:
		return errors.New("you must specify two or three arguments: verb, resource, and optional resourceName")
	}
	return nil
}
