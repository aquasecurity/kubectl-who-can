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

  # List who can read pod logs
  kubectl who-can get pods --subresource=log

  # List who can access the URL /logs/
  kubectl who-can get /logs`
)

type role struct {
	name          string
	isClusterRole bool
}

type roles map[role]struct{}

type whoCan struct {
	verb           string
	resource       string
	nonResourceURL string
	subResource    string
	resourceName   string

	namespace     string
	allNamespaces bool

	configFlags     *clioptions.ConfigFlags
	clientConfig    clientcmd.ClientConfig
	clientNamespace clientcore.NamespaceInterface
	clientRBAC      clientrbac.RbacV1Interface

	namespaceValidator NamespaceValidator
	resourceResolver   ResourceResolver
	accessChecker      AccessChecker

	r roles

	clioptions.IOStreams
}

func NewWhoCanOptions(configFlags *clioptions.ConfigFlags,
	clientConfig clientcmd.ClientConfig,
	clientNamespace clientcore.NamespaceInterface,
	clientRBAC clientrbac.RbacV1Interface,
	namespaceValidator NamespaceValidator,
	resourceResolver ResourceResolver,
	accessChecker AccessChecker,
	streams clioptions.IOStreams) *whoCan {
	return &whoCan{
		configFlags:        configFlags,
		clientConfig:       clientConfig,
		clientNamespace:    clientNamespace,
		clientRBAC:         clientRBAC,
		namespaceValidator: namespaceValidator,
		resourceResolver:   resourceResolver,
		accessChecker:      accessChecker,
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

	cmd.PersistentFlags().StringVar(&o.subResource, "subresource", o.subResource, "SubResource such as pod/log or deployment/scale")
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
	} else {
		resourceTokens := strings.SplitN(args[1], "/", 2)
		w.resource = resourceTokens[0]
		if len(resourceTokens) > 1 {
			w.resourceName = resourceTokens[1]
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

	w.r = make(map[role]struct{}, 10)

	// Get the Roles that relate to the Verbs and Resources we are interested in
	err = w.getRoles()
	if err != nil {
		return fmt.Errorf("getting Roles: %v", err)
	}

	// Get the RoleBindings that relate to this set of Roles
	roleBindings, err := w.getRoleBindings()
	if err != nil {
		return fmt.Errorf("getting RoleBindings: %v", err)
	}

	// Get the ClusterRoles that relate to the verbs and resources we are interested in
	err = w.getClusterRoles()
	if err != nil {
		return fmt.Errorf("getting ClusterRoles: %v", err)
	}

	// Get the ClusterRoleBindings that relate to this set of ClusterRoles
	clusterRoleBindings, err := w.getClusterRoleBindings()
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

func (w *whoCan) getRoles() error {
	rl, err := w.clientRBAC.Roles(w.namespace).List(meta.ListOptions{})
	if err != nil {
		return err
	}

	w.filterRoles(rl)
	return nil
}

func (w *whoCan) filterRoles(roles *rbac.RoleList) {
	for _, item := range roles.Items {
		for _, rule := range item.Rules {
			if !w.policyRuleMatches(rule) {
				glog.V(3).Infof("Role [%s] doesn't match policy filter", item.Name)
				continue
			}

			newRole := role{
				name:          item.Name,
				isClusterRole: false,
			}
			if _, ok := w.r[newRole]; !ok {
				w.r[newRole] = struct{}{}
			}

		}
	}
}

func (w *whoCan) getClusterRoles() error {
	crl, err := w.clientRBAC.ClusterRoles().List(meta.ListOptions{})
	if err != nil {
		return err
	}

	w.filterClusterRoles(crl)
	return nil
}

func (w *whoCan) filterClusterRoles(roles *rbac.ClusterRoleList) {
	for _, item := range roles.Items {
		for _, rule := range item.Rules {
			if !w.policyRuleMatches(rule) {
				glog.V(3).Infof("ClusterRole [%s] doesn't match policy filter", item.Name)
				continue
			}

			newRole := role{
				name:          item.Name,
				isClusterRole: true,
			}
			if _, ok := w.r[newRole]; !ok {
				w.r[newRole] = struct{}{}
			}
		}
	}
}

func (w *whoCan) policyRuleMatches(rule rbac.PolicyRule) bool {
	if w.nonResourceURL != "" {
		return w.matchesVerb(rule) &&
			w.matchesNonResourceURL(rule)
	}

	return w.matchesVerb(rule) &&
		w.matchesResource(rule) &&
		w.matchesResourceName(rule)
}

func (w *whoCan) matchesVerb(rule rbac.PolicyRule) bool {
	for _, verb := range rule.Verbs {
		if verb == rbac.VerbAll || verb == w.verb {
			return true
		}
	}
	return false
}

func (w *whoCan) matchesResource(rule rbac.PolicyRule) bool {
	for _, resource := range rule.Resources {
		if resource == rbac.ResourceAll || resource == w.resource {
			return true
		}
	}
	return false
}

func (w *whoCan) matchesResourceName(rule rbac.PolicyRule) bool {
	if w.resourceName == "" && len(rule.ResourceNames) == 0 {
		return true
	}
	if len(rule.ResourceNames) == 0 {
		return true
	}
	for _, name := range rule.ResourceNames {
		if name == w.resourceName {
			return true
		}
	}
	return false
}

func (w *whoCan) matchesNonResourceURL(rule rbac.PolicyRule) bool {
	for _, URL := range rule.NonResourceURLs {
		if URL == w.nonResourceURL {
			return true
		}
	}
	return false
}

func (w *whoCan) getRoleBindings() (roleBindings []rbac.RoleBinding, err error) {
	rbl, err := w.clientRBAC.RoleBindings(w.namespace).List(meta.ListOptions{})
	if err != nil {
		return
	}

	for _, roleBinding := range rbl.Items {
		if w.r.match(&roleBinding.RoleRef) {
			glog.V(1).Info(fmt.Sprintf("Match found: roleRef: %v", roleBinding.RoleRef))
			roleBindings = append(roleBindings, roleBinding)
		}
	}

	return
}

func (w *whoCan) getClusterRoleBindings() (clusterRoleBindings []rbac.ClusterRoleBinding, err error) {
	rbl, err := w.clientRBAC.ClusterRoleBindings().List(meta.ListOptions{})
	if err != nil {
		return
	}

	for _, roleBinding := range rbl.Items {
		if w.r.match(&roleBinding.RoleRef) {
			glog.V(1).Info(fmt.Sprintf("Match found: roleRef: %v", roleBinding.RoleRef))
			clusterRoleBindings = append(clusterRoleBindings, roleBinding)
		}
	}

	return
}

func (r roles) match(roleRef *rbac.RoleRef) bool {
	tempRole := role{
		name:          roleRef.Name,
		isClusterRole: (roleRef.Kind == "ClusterRole"),
	}

	glog.V(3).Info(fmt.Sprintf("Testing against roleRef: %v", tempRole))

	_, ok := r[tempRole]
	return ok
}

func (w *whoCan) output(roleBindings []rbac.RoleBinding, clusterRoleBindings []rbac.ClusterRoleBinding) {
	wr := new(tabwriter.Writer)
	wr.Init(w.Out, 0, 8, 2, ' ', 0)

	action := w.prettyPrintAction()

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

func (w *whoCan) prettyPrintAction() string {
	if w.nonResourceURL != "" {
		return fmt.Sprintf("%s %s", w.verb, w.nonResourceURL)
	}
	name := w.resourceName
	if name != "" {
		name = "/" + name
	}
	return fmt.Sprintf("%s %s%s", w.verb, w.resource, name)
}
