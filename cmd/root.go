package cmd

import (
	"errors"
	"flag"
	"fmt"
	v1 "k8s.io/api/core/v1"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Deprecated TODO At some point we should get rid of global vars and init func.
var namespaceFlag string

// RootCmd is the command we're going to run
var RootCmd = &cobra.Command{
	Use:   "kubectl-who-can VERB TYPE [NAME]",
	Short: "who-can shows which users, groups and service accounts can perform a given action",
	Long:  "who-can shows which users, groups and service accounts can perform a given verb on a given resource type",
	Example: `  # List who can get pods in all namespaces:
  kubectl-who-can get pods

  # List who can create services in the foo namespace:
  kubectl-who-can create services -n foo

  # List who can get the mongodb service in the bar namespace:
  kubectl-who-can get services mongodb --namespace bar`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return errors.New("please specify at least a verb and a resource type")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		w := whoCan{}
		w.verb = args[0]
		w.resource = args[1]
		if len(args) > 2 {
			w.resourceName = args[2]
		}
		w.namespace = namespaceFlag

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

		// TODO Introduce proper dependency injection with NewCmdWhoCan(NewAPIAccessChecker(client), ...)
		w.accessChecker = NewAPIAccessChecker(w.client.AuthorizationV1().SelfSubjectAccessReviews())

		if err := w.do(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&namespaceFlag, "namespace", "n", v1.NamespaceAll,
		"if present, the namespace scope for the CLI request")

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
