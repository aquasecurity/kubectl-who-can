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

var namespace string

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
  kubectl-who-can get service mongodb --namespace bar`,
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

		warnings, err := checkAPIAccess(NewAPIAccessChecker(w.client))
		if err != nil {
			fmt.Printf("Error checking API access: %v\n", err)
			os.Exit(1)
		}
		printAPIAccessWarnings(warnings)

		if err := w.do(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func checkAPIAccess(checker APIAccessChecker) ([]string, error) {
	var warnings []string
	checks := []struct {
		verb     string
		resource string
	}{
		{verb: "list", resource: "roles"},
		{verb: "list", resource: "rolebindings"},
		{verb: "list", resource: "clusterroles"},
		{verb: "list", resource: "clusterrolebindings"},
	}
	for _, check := range checks {
		allowed, err := checker.IsAllowedTo(check.verb, check.resource)
		if err != nil {
			return nil, err
		}
		if !allowed {
			warnings = append(warnings, fmt.Sprintf("The user is not allowed to %s %s", check.verb, check.resource))
		}
	}

	return warnings, nil
}

func printAPIAccessWarnings(warnings []string) {
	if len(warnings) > 0 {
		fmt.Println("Warning: The list might not be complete due to missing permission(s):")
		for _, warning := range warnings {
			fmt.Printf("  %s\n", warning)
		}
		fmt.Println()
	}
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", v1.NamespaceAll,
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
