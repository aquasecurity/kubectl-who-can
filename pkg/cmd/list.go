package cmd

import (
	"errors"
	"flag"
	"fmt"
	"github.com/spf13/cobra"
	core "k8s.io/api/core/v1"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	clientcore "k8s.io/client-go/kubernetes/typed/core/v1"
	clientrbac "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/tools/clientcmd"
	"strings"
	"text/tabwriter"

	"github.com/golang/glog"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	whoCanUsage = `kubectl who-can VERB [TYPE | TYPE/NAME | NONRESOURCEURL]`
	whoCanLong  = `Shows which users, groups and service accounts can perform a given verb on a given resource type.

VERB is a logical Kubernetes API verb like 'get', 'list', 'watch', 'delete', etc.
TYPE is a Kubernetes resource. Shortcuts, such as 'pod' or 'po' will be resolved. NAME is the name of a particular Kubernetes resource.
NONRESOURCEURL is a partial URL that starts with "/".`
	whoCanExample = `  # List who can get pods in any namespace
  kubectl who-can get pods --all-namespaces

  # List who can create pods in the current namespace
  kubectl who-can create pods

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
)

// Action represents an action a subject can be given permission to.
type Action struct {
	verb           string
	resource       string
	nonResourceURL string
	subResource    string
	resourceName   string

	namespace     string
	allNamespaces bool
}

// roles is a set of Role names matching the specified Action.
type roles map[string]struct{}

// clusterRoles is a set of ClusterRole names matching the specified Action
type clusterRoles map[string]struct{}

type whoCan struct {
	Action

	configFlags     *clioptions.ConfigFlags
	clientConfig    clientcmd.ClientConfig
	clientNamespace clientcore.NamespaceInterface
	clientRBAC      clientrbac.RbacV1Interface

	namespaceValidator NamespaceValidator
	resourceResolver   ResourceResolver
	accessChecker      AccessChecker
	policyRuleMatcher  PolicyRuleMatcher

	clioptions.IOStreams
}

func NewWhoCanOptions(configFlags *clioptions.ConfigFlags,
	clientConfig clientcmd.ClientConfig,
	clientNamespace clientcore.NamespaceInterface,
	clientRBAC clientrbac.RbacV1Interface,
	namespaceValidator NamespaceValidator,
	resourceResolver ResourceResolver,
	accessChecker AccessChecker,
	policyRuleMatcher PolicyRuleMatcher,
	streams clioptions.IOStreams) *whoCan {
	return &whoCan{
		configFlags:        configFlags,
		clientConfig:       clientConfig,
		clientNamespace:    clientNamespace,
		clientRBAC:         clientRBAC,
		namespaceValidator: namespaceValidator,
		resourceResolver:   resourceResolver,
		accessChecker:      accessChecker,
		policyRuleMatcher:  policyRuleMatcher,
		IOStreams:          streams,
	}
}

func NewCmdWhoCan(streams clioptions.IOStreams) (*cobra.Command, error) {
	configFlags := clioptions.NewConfigFlags(true)

	clientConfig, err := configFlags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("getting config: %v", err)
	}

	client, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("creating client: %v", err)
	}

	mapper, err := configFlags.ToRESTMapper()
	if err != nil {
		return nil, fmt.Errorf("getting mapper: %v", err)
	}

	clientNamespace := client.CoreV1().Namespaces()
	accessChecker := NewAccessChecker(client.AuthorizationV1().SelfSubjectAccessReviews())
	namespaceValidator := NewNamespaceValidator(clientNamespace)
	resourceResolver := NewResourceResolver(client.Discovery(), mapper)

	o := NewWhoCanOptions(configFlags,
		configFlags.ToRawKubeConfigLoader(),
		clientNamespace,
		client.RbacV1(),
		namespaceValidator,
		resourceResolver,
		accessChecker,
		NewPolicyRuleMatcher(),
		streams)

	cmd := &cobra.Command{
		Use:          whoCanUsage,
		Long:         whoCanLong,
		Example:      whoCanExample,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Complete(args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			if err := o.Check(); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&o.subResource, "subresource", o.subResource,
		"SubResource such as pod/log or deployment/scale")
	cmd.PersistentFlags().BoolVarP(&o.allNamespaces, "all-namespaces", "A", false,
		"If true, check the specified action in all namespaces.")

	flag.CommandLine.VisitAll(func(goflag *flag.Flag) {
		cmd.PersistentFlags().AddGoFlag(goflag)
	})
	configFlags.AddFlags(cmd.Flags())

	return cmd, nil
}

// Complete sets all information required to check who can perform the specified action.
func (w *whoCan) Complete(args []string) error {
	err := w.resolveArgs(args)
	if err != nil {
		return err
	}

	if w.resource != "" {
		w.resource, err = w.resourceResolver.Resolve(w.verb, w.resource, w.subResource)
		if err != nil {
			return fmt.Errorf("resolving resource: %v", err)
		}
		glog.V(3).Infof("Resolved resource `%s`", w.resource)
	}

	err = w.resolveNamespace()
	if err != nil {
		return err
	}

	return nil
}

func (w *whoCan) resolveArgs(args []string) error {
	if len(args) < 2 {
		return errors.New("you must specify two or three arguments: verb, resource, and optional resourceName")
	}

	w.verb = args[0]
	if strings.HasPrefix(args[1], "/") {
		w.nonResourceURL = args[1]
		glog.V(3).Infof("Resolved nonResourceURL `%s`", w.nonResourceURL)
	} else {
		resourceTokens := strings.SplitN(args[1], "/", 2)
		w.resource = resourceTokens[0]
		if len(resourceTokens) > 1 {
			w.resourceName = resourceTokens[1]
			glog.V(3).Infof("Resolved resourceName `%s`", w.resourceName)
		}
	}
	return nil
}

func (w *whoCan) resolveNamespace() (err error) {
	if w.allNamespaces {
		w.namespace = core.NamespaceAll
		glog.V(3).Infof("Resolved namespace `%s` from --all-namespaces flag", w.namespace)
		return nil
	}

	if w.configFlags.Namespace != nil && *w.configFlags.Namespace != "" {
		w.namespace = *w.configFlags.Namespace
		glog.V(3).Infof("Resolved namespace `%s` from --namespace flag", w.namespace)
		return nil
	}

	// Neither --all-namespaces nor --namespace flag was specified
	w.namespace, _, err = w.clientConfig.Namespace()
	if err != nil {
		return fmt.Errorf("getting namespace from current context: %v", err)
	}
	glog.V(3).Infof("Resolved namespace `%s` from current context", w.namespace)
	return nil
}

// Validate makes sure that provided args and flags are valid.
func (w *whoCan) Validate() error {
	if w.nonResourceURL != "" && w.subResource != "" {
		return fmt.Errorf("--subresource cannot be used with NONRESOURCEURL")
	}

	err := w.namespaceValidator.Validate(w.namespace)
	if err != nil {
		return fmt.Errorf("validating namespace: %v", err)
	}

	return nil
}

// Check checks who can perform the action specified by WhoCanOptions and prints the results to the standard output.
func (w *whoCan) Check() error {
	warnings, err := w.checkAPIAccess()
	if err != nil {
		return fmt.Errorf("checking API access: %v", err)
	}

	// Get the Roles that relate to the Verbs and Resources we are interested in
	roleNames, err := w.GetRolesFor(w.Action)
	if err != nil {
		return fmt.Errorf("getting Roles: %v", err)
	}

	// Get the ClusterRoles that relate to the verbs and resources we are interested in
	clusterRoleNames, err := w.GetClusterRolesFor(w.Action)
	if err != nil {
		return fmt.Errorf("getting ClusterRoles: %v", err)
	}

	glog.V(4).Infof("Role names matching the action filter: %v", roleNames)
	glog.V(4).Infof("ClusterRole names matching the action filter: %v", clusterRoleNames)

	// Get the RoleBindings that relate to this set of Roles
	roleBindings, err := w.GetRoleBindings(roleNames)
	if err != nil {
		return fmt.Errorf("getting RoleBindings: %v", err)
	}

	// Get the ClusterRoleBindings that relate to this set of ClusterRoles
	clusterRoleBindings, err := w.GetClusterRoleBindings(clusterRoleNames)
	if err != nil {
		return fmt.Errorf("getting ClusterRoleBindings: %v", err)
	}

	// Output warnings
	w.printAPIAccessWarnings(warnings)

	// Output the results
	w.output(roleBindings, clusterRoleBindings)

	return nil
}

func (w *whoCan) checkAPIAccess() ([]string, error) {
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

func (w *whoCan) printAPIAccessWarnings(warnings []string) {
	if len(warnings) > 0 {
		_, _ = fmt.Fprintln(w.Out, "Warning: The list might not be complete due to missing permission(s):")
		for _, warning := range warnings {
			_, _ = fmt.Fprintf(w.Out, "\t%s\n", warning)
		}
		_, _ = fmt.Fprintln(w.Out)
	}
}

// GetRolesFor returns a set of names of Roles matching the specified Action.
func (w *whoCan) GetRolesFor(action Action) (roles, error) {
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
func (w *whoCan) GetClusterRolesFor(action Action) (clusterRoles, error) {
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

// GetRoleBindings returns the RoleBindings that refer to the given set of Role names.
func (w *whoCan) GetRoleBindings(roleNames roles) (roleBindings []rbac.RoleBinding, err error) {
	list, err := w.clientRBAC.RoleBindings(w.namespace).List(meta.ListOptions{})
	if err != nil {
		return
	}

	for _, roleBinding := range list.Items {
		if _, ok := roleNames[roleBinding.RoleRef.Name]; ok {
			roleBindings = append(roleBindings, roleBinding)
		}
	}

	return
}

// GetClusterRoleBindings returns the ClusterRoleBindings that refer to the given sef of ClusterRole names.
func (w *whoCan) GetClusterRoleBindings(clusterRoleNames clusterRoles) (clusterRoleBindings []rbac.ClusterRoleBinding, err error) {
	list, err := w.clientRBAC.ClusterRoleBindings().List(meta.ListOptions{})
	if err != nil {
		return
	}

	for _, roleBinding := range list.Items {
		if _, ok := clusterRoleNames[roleBinding.RoleRef.Name]; ok {
			//if w.clusterRoleBindingMatches(&roleBinding, clusterRoleNames) {
			clusterRoleBindings = append(clusterRoleBindings, roleBinding)
		}
	}

	return
}

func (w *whoCan) output(roleBindings []rbac.RoleBinding, clusterRoleBindings []rbac.ClusterRoleBinding) {
	wr := new(tabwriter.Writer)
	wr.Init(w.Out, 0, 8, 2, ' ', 0)

	action := w.Action.PrettyPrint()

	if w.resource != "" {
		// NonResourceURL permissions can only be granted through ClusterRoles. Hence no point in printing RoleBindings section.
		if len(roleBindings) == 0 {
			fmt.Fprintf(w.Out, "No subjects found with permissions to %s assigned through RoleBindings\n", action)
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
		fmt.Fprintf(w.Out, "No subjects found with permissions to %s assigned through ClusterRoleBindings\n", action)
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
