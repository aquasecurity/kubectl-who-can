package cmd

import (
	"errors"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"io"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	clientcore "k8s.io/client-go/kubernetes/typed/core/v1"
	clientrbac "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/tools/clientcmd"
	"strings"
	"text/tabwriter"
)

const (
	whoCanUsage = `kubectl who-can VERB (TYPE | TYPE/NAME | NONRESOURCEURL)`
	whoCanLong  = `Shows which users, groups and service accounts can perform a given verb on a given resource type.

VERB is a logical Kubernetes API verb like 'get', 'list', 'watch', 'delete', etc.
TYPE is a Kubernetes resource. Shortcuts and API groups will be resolved, e.g. 'po' or 'pods.metrics.k8s.io'.
NAME is the name of a particular Kubernetes resource.
NONRESOURCEURL is a partial URL that starts with "/".`
	whoCanExample = `  # List who can get pods from any of the available namespaces
  kubectl who-can get pods --all-namespaces

  # List who can create pods in the current namespace
  kubectl who-can create pods

  # List who can get pods specifying the API group
  kubectl who-can get pods.metrics.k8s.io

  # List who can create services in namespace "foo"
  kubectl who-can create services -n foo

  # List who can get the service named "mongodb" in namespace "bar"
  kubectl who-can get svc/mongodb --namespace bar

  # List who can do everything with pods in the current namespace
  kubectl who-can '*' pods

  # List who can list every resource in the namespace "baz"
  kubectl who-can list '*' -n baz

  # List who can read pod logs
  kubectl who-can get pods --subresource=log

  # List who can access the URL /logs/
  kubectl who-can get /logs`

	// RoleKind is the RoleRef's Kind referencing a Role.
	RoleKind = "Role"
	// ClusterRoleKind is the RoleRef's Kind referencing a ClusterRole.
	ClusterRoleKind = "ClusterRole"

	subResourceFlag   = "subresource"
	allNamespacesFlag = "all-namespaces"
	namespaceFlag     = "namespace"
)

// Action represents an action a subject can be given permission to.
type Action struct {
	verb           string
	resource       string
	nonResourceURL string
	subResource    string
	resourceName   string
	gr             schema.GroupResource

	namespace     string
	allNamespaces bool
}

// roles is a set of Role names matching the specified Action.
type roles map[string]struct{}

// clusterRoles is a set of ClusterRole names matching the specified Action.
type clusterRoles map[string]struct{}

type WhoCan struct {
	Action

	clientConfig    clientcmd.ClientConfig
	clientNamespace clientcore.NamespaceInterface
	clientRBAC      clientrbac.RbacV1Interface

	namespaceValidator NamespaceValidator
	resourceResolver   ResourceResolver
	accessChecker      AccessChecker
	policyRuleMatcher  PolicyRuleMatcher
}

func NewWhoCan(clientConfig clientcmd.ClientConfig, mapper apimeta.RESTMapper) (*WhoCan, error) {
	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	clientNamespace := client.CoreV1().Namespaces()

	return &WhoCan{
		clientConfig:       clientConfig,
		clientNamespace:    clientNamespace,
		clientRBAC:         client.RbacV1(),
		namespaceValidator: NewNamespaceValidator(clientNamespace),
		resourceResolver:   NewResourceResolver(client.Discovery(), mapper),
		accessChecker:      NewAccessChecker(client.AuthorizationV1().SelfSubjectAccessReviews()),
		policyRuleMatcher:  NewPolicyRuleMatcher(),
	}, nil
}

func NewWhoCanCommand(streams clioptions.IOStreams) (*cobra.Command, error) {
	var configFlags *clioptions.ConfigFlags

	cmd := &cobra.Command{
		Use:          whoCanUsage,
		Long:         whoCanLong,
		Example:      whoCanExample,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := configFlags.ToRawKubeConfigLoader()

			mapper, err := configFlags.ToRESTMapper()
			if err != nil {
				return fmt.Errorf("getting mapper: %v", err)
			}

			o, err := NewWhoCan(clientConfig, mapper)
			if err != nil {
				return err
			}

			action, err := ResolveAction(clientConfig, cmd.Flags(), args)
			if err != nil {
				return err
			}
			// FIXME This is just intermediate step. At the end the Check() method should accept action as arg.
			o.Action = action

			warnings, err := o.CheckAPIAccess()
			if err != nil {
				return err
			}

			// Output warnings
			o.PrintWarnings(streams.Out, warnings)

			roleBindings, clusterRoleBindings, err := o.Check()
			if err != nil {
				return err
			}

			// Output check results
			o.PrintChecks(streams.Out, roleBindings, clusterRoleBindings)

			return nil
		},
	}

	cmd.Flags().String("subresource", "", "SubResource such as pod/log or deployment/scale")
	cmd.Flags().BoolP("all-namespaces", "A", false, "If true, check for users that can do the specified action in any of the available namespaces")

	flag.CommandLine.VisitAll(func(gf *flag.Flag) {
		cmd.Flags().AddGoFlag(gf)
	})
	configFlags = clioptions.NewConfigFlags(true)
	configFlags.AddFlags(cmd.Flags())

	return cmd, nil
}

// Complete sets all information required to check who can perform the specified action.
func ResolveAction(clientConfig clientcmd.ClientConfig, flags *pflag.FlagSet, args []string) (action Action, err error) {
	if len(args) < 2 {
		err = errors.New("you must specify two or three arguments: verb, resource, and optional resourceName")
		return
	}

	action.verb = args[0]
	if strings.HasPrefix(args[1], "/") {
		action.nonResourceURL = args[1]
		glog.V(3).Infof("Resolved nonResourceURL `%s`", action.nonResourceURL)
	} else {
		resourceTokens := strings.SplitN(args[1], "/", 2)
		action.resource = resourceTokens[0]
		if len(resourceTokens) > 1 {
			action.resourceName = resourceTokens[1]
			glog.V(3).Infof("Resolved resourceName `%s`", action.resourceName)
		}
	}

	action.subResource, err = flags.GetString(subResourceFlag)
	if err != nil {
		return
	}

	action.allNamespaces, err = flags.GetBool(allNamespacesFlag)
	if err != nil {
		return
	}

	if action.allNamespaces {
		action.namespace = core.NamespaceAll
		glog.V(3).Infof("Resolved namespace `%s` from --all-namespaces flag", action.namespace)
		return
	}

	action.namespace, err = flags.GetString(namespaceFlag)
	if err != nil {
		return
	}

	if action.namespace != "" {
		glog.V(3).Infof("Resolved namespace `%s` from --namespace flag", action.namespace)
		return
	}

	// Neither --all-namespaces nor --namespace flag was specified
	action.namespace, _, err = clientConfig.Namespace()
	if err != nil {
		err = fmt.Errorf("getting namespace from current context: %v", err)
	}
	glog.V(3).Infof("Resolved namespace `%s` from current context", action.namespace)
	return
}

// Validate makes sure that provided args and flags are valid.
func (w *WhoCan) validate() error {
	if w.nonResourceURL != "" && w.subResource != "" {
		return fmt.Errorf("--subresource cannot be used with NONRESOURCEURL")
	}

	err := w.namespaceValidator.Validate(w.namespace)
	if err != nil {
		return fmt.Errorf("validating namespace: %v", err)
	}

	return nil
}

// Check checks who can perform the action specified by WhoCanOptions and returns the role bindings that allows the
// action to be performed.
func (w *WhoCan) Check() (roleBindings []rbac.RoleBinding, clusterRoleBindings []rbac.ClusterRoleBinding, err error) {
	err = w.validate()
	if err != nil {
		err = fmt.Errorf("validationg args: %v", err)
		return
	}

	if w.resource != "" {
		w.gr, err = w.resourceResolver.Resolve(w.verb, w.resource, w.subResource)
		if err != nil {
			err = fmt.Errorf("resolving resource: %v", err)
			return
		}
		glog.V(3).Infof("Resolved resource `%s`", w.gr.String())
	}

	// Get the Roles that relate to the Verbs and Resources we are interested in
	roleNames, err := w.GetRolesFor(w.Action)
	if err != nil {
		return []rbac.RoleBinding{}, []rbac.ClusterRoleBinding{}, fmt.Errorf("getting Roles: %v", err)
	}

	// Get the ClusterRoles that relate to the verbs and resources we are interested in
	clusterRoleNames, err := w.GetClusterRolesFor(w.Action)
	if err != nil {
		return []rbac.RoleBinding{}, []rbac.ClusterRoleBinding{}, fmt.Errorf("getting ClusterRoles: %v", err)
	}

	// Get the RoleBindings that relate to this set of Roles or ClusterRoles
	roleBindings, err = w.GetRoleBindings(roleNames, clusterRoleNames)
	if err != nil {
		err = fmt.Errorf("getting RoleBindings: %v", err)
		return
	}

	// Get the ClusterRoleBindings that relate to this set of ClusterRoles
	clusterRoleBindings, err = w.GetClusterRoleBindings(clusterRoleNames)
	if err != nil {
		err = fmt.Errorf("getting ClusterRoleBindings: %v", err)
		return
	}

	return
}

func (w *WhoCan) CheckAPIAccess() ([]string, error) {
	type check struct {
		verb      string
		resource  string
		namespace string
	}

	var checks []check
	var warnings []string

	// Determine which checks need to be executed.
	if w.namespace == "" {
		checks = append(checks, check{"list", "namespaces", ""})

		nsList, err := w.clientNamespace.List(meta.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing namespaces: %v", err)
		}
		for _, ns := range nsList.Items {
			checks = append(checks, check{"list", "roles", ns.Name})
			checks = append(checks, check{"list", "rolebindings", ns.Name})
		}
	} else {
		checks = append(checks, check{"list", "roles", w.namespace})
		checks = append(checks, check{"list", "rolebindings", w.namespace})
	}

	// Actually run the checks and collect warnings.
	for _, check := range checks {
		allowed, err := w.accessChecker.IsAllowedTo(check.verb, check.resource, check.namespace)
		if err != nil {
			return nil, err
		}
		if !allowed {
			var msg string

			if check.namespace == "" {
				msg = fmt.Sprintf("The user is not allowed to %s %s", check.verb, check.resource)
			} else {
				msg = fmt.Sprintf("The user is not allowed to %s %s in the %s namespace", check.verb, check.resource, check.namespace)
			}

			warnings = append(warnings, msg)
		}
	}

	return warnings, nil
}

// GetRolesFor returns a set of names of Roles matching the specified Action.
func (w *WhoCan) GetRolesFor(action Action) (roles, error) {
	rl, err := w.clientRBAC.Roles(w.namespace).List(meta.ListOptions{})
	if err != nil {
		return nil, err
	}

	roleNames := make(map[string]struct{}, 10)

	for _, item := range rl.Items {
		if w.policyRuleMatcher.MatchesRole(item, action) {
			if _, ok := roleNames[item.Name]; !ok {
				roleNames[item.Name] = struct{}{}
			}
		}
	}

	return roleNames, nil
}

// GetClusterRolesFor returns a set of names of ClusterRoles matching the specified Action.
func (w *WhoCan) GetClusterRolesFor(action Action) (clusterRoles, error) {
	crl, err := w.clientRBAC.ClusterRoles().List(meta.ListOptions{})
	if err != nil {
		return nil, err
	}

	cr := make(map[string]struct{}, 10)

	for _, item := range crl.Items {
		if w.policyRuleMatcher.MatchesClusterRole(item, action) {
			if _, ok := cr[item.Name]; !ok {
				cr[item.Name] = struct{}{}
			}
		}
	}
	return cr, nil
}

// GetRoleBindings returns the RoleBindings that refer to the given set of Role names or ClusterRole names.
func (w *WhoCan) GetRoleBindings(roleNames roles, clusterRoleNames clusterRoles) (roleBindings []rbac.RoleBinding, err error) {
	// TODO I'm wondering if GetRoleBindings should be invoked at all when the --all-namespaces flag is specified?
	if w.namespace == core.NamespaceAll {
		return
	}

	list, err := w.clientRBAC.RoleBindings(w.namespace).List(meta.ListOptions{})
	if err != nil {
		return
	}

	for _, roleBinding := range list.Items {
		if roleBinding.RoleRef.Kind == RoleKind {
			if _, ok := roleNames[roleBinding.RoleRef.Name]; ok {
				roleBindings = append(roleBindings, roleBinding)
			}
		} else if roleBinding.RoleRef.Kind == ClusterRoleKind {
			if _, ok := clusterRoleNames[roleBinding.RoleRef.Name]; ok {
				roleBindings = append(roleBindings, roleBinding)
			}
		}
	}

	return
}

// GetClusterRoleBindings returns the ClusterRoleBindings that refer to the given sef of ClusterRole names.
func (w *WhoCan) GetClusterRoleBindings(clusterRoleNames clusterRoles) (clusterRoleBindings []rbac.ClusterRoleBinding, err error) {
	list, err := w.clientRBAC.ClusterRoleBindings().List(meta.ListOptions{})
	if err != nil {
		return
	}

	for _, roleBinding := range list.Items {
		if _, ok := clusterRoleNames[roleBinding.RoleRef.Name]; ok {
			clusterRoleBindings = append(clusterRoleBindings, roleBinding)
		}
	}

	return
}

func (w *WhoCan) PrintWarnings(out io.Writer, warnings []string) {
	if len(warnings) > 0 {
		_, _ = fmt.Fprintln(out, "Warning: The list might not be complete due to missing permission(s):")
		for _, warning := range warnings {
			_, _ = fmt.Fprintf(out, "\t%s\n", warning)
		}
		_, _ = fmt.Fprintln(out)
	}
}

func (w *WhoCan) PrintChecks(out io.Writer, roleBindings []rbac.RoleBinding, clusterRoleBindings []rbac.ClusterRoleBinding) {
	wr := new(tabwriter.Writer)
	wr.Init(out, 0, 8, 2, ' ', 0)

	action := w.Action.PrettyPrint()

	if w.resource != "" {
		// NonResourceURL permissions can only be granted through ClusterRoles. Hence no point in printing RoleBindings section.
		if len(roleBindings) == 0 {
			fmt.Fprintf(out, "No subjects found with permissions to %s assigned through RoleBindings\n", action)
		} else {
			fmt.Fprintln(wr, "ROLEBINDING\tNAMESPACE\tSUBJECT\tTYPE\tSA-NAMESPACE")
			for _, rb := range roleBindings {
				for _, s := range rb.Subjects {
					fmt.Fprintf(wr, "%s\t%s\t%s\t%s\t%s\n", rb.Name, rb.GetNamespace(), s.Name, s.Kind, s.Namespace)
				}
			}
		}

		fmt.Fprintln(wr)
	}

	if len(clusterRoleBindings) == 0 {
		fmt.Fprintf(out, "No subjects found with permissions to %s assigned through ClusterRoleBindings\n", action)
	} else {
		fmt.Fprintln(wr, "CLUSTERROLEBINDING\tSUBJECT\tTYPE\tSA-NAMESPACE")
		for _, rb := range clusterRoleBindings {
			for _, s := range rb.Subjects {
				fmt.Fprintf(wr, "%s\t%s\t%s\t%s\n", rb.Name, s.Name, s.Kind, s.Namespace)
			}
		}
	}
	wr.Flush()
}

func (w Action) PrettyPrint() string {
	if w.nonResourceURL != "" {
		return fmt.Sprintf("%s %s", w.verb, w.nonResourceURL)
	}
	name := w.resourceName
	if name != "" {
		name = "/" + name
	}
	return fmt.Sprintf("%s %s%s", w.verb, w.resource, name)
}
