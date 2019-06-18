package cmd

import (
	"errors"
	"flag"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	core "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	clientcore "k8s.io/client-go/kubernetes/typed/core/v1"
	clientrbac "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"os"
	"text/tabwriter"

	"github.com/golang/glog"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type role struct {
	name          string
	isClusterRole bool
}

type roles map[role]struct{}

// TODO Rename whoCan to WhoCanOptions
type whoCan struct {
	verb         string
	resource     string
	resourceName string
	subResource  string

	namespace     string
	allNamespaces bool

	configFlags        *genericclioptions.ConfigFlags
	namespaces         clientcore.NamespaceInterface
	rbac               clientrbac.RbacV1Interface
	namespaceValidator NamespaceValidator
	resourceResolver   ResourceResolver
	accessChecker      APIAccessChecker

	r           roles
	apiResource meta.APIResource
}

func NewWhoCanOptions(config *genericclioptions.ConfigFlags) *whoCan {
	return &whoCan{
		configFlags: config,
	}
}

func NewCmdWhoCan() *cobra.Command {
	o := NewWhoCanOptions(genericclioptions.NewConfigFlags(true))

	cmd := &cobra.Command{
		Use:   "kubectl-who-can VERB TYPE [NAME]",
		Short: "who-can shows which users, groups and service accounts can perform a given action",
		Long:  "who-can shows which users, groups and service accounts can perform a given verb on a given resource type",
		Example: `  # List who can get pods in any namespace
  kubectl who-can get pods --all-namespaces

  # List who can create pods in the current namespace
  kubectl who-can create pods

  # List who can create services in namespace "foo"
  kubectl who-can create services -n foo

  # List who can get the service named "mongodb" in namespace "bar"
  kubectl who-can get svc mongodb --namespace bar

  # List who can read pod logs
  kubectl who-can get pods --subresource=log`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return errors.New("please specify at least a verb and a resource type")
			}
			return nil
		},
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
	cmd.PersistentFlags().StringVarP(&o.namespace, "namespace", "n", core.NamespaceAll,
		"if present, the namespace scope for the CLI request")
	cmd.PersistentFlags().BoolVarP(&o.allNamespaces, "all-namespaces", "A", false,
		"If true, check the specified action in all namespaces.")

	flag.CommandLine.VisitAll(func(goflag *flag.Flag) {
		cmd.PersistentFlags().AddGoFlag(goflag)
	})
	o.configFlags.AddFlags(cmd.Flags())

	return cmd
}

// Complete sets all information required to check who can perform the specified action.
func (w *whoCan) Complete(args []string) error {
	var err error
	if w.allNamespaces {
		w.namespace = core.NamespaceAll
	}

	if !w.allNamespaces && w.namespace == "" {
		w.namespace, _, err = w.configFlags.ToRawKubeConfigLoader().Namespace()
		if err != nil {
			return fmt.Errorf("getting namespace from current context: %v\n", err)
		}
	}

	w.verb = args[0]
	w.resource = args[1]
	if len(args) > 2 {
		w.resourceName = args[2]
	}

	clientConfig, err := w.configFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("getting config: %v", err)
	}

	client, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return fmt.Errorf("creating client: %v", err)
	}

	mapper, err := w.configFlags.ToRESTMapper()
	if err != nil {
		return fmt.Errorf("getting mapper: %v", err)
	}

	w.namespaces = client.CoreV1().Namespaces()
	w.rbac = client.RbacV1()
	w.accessChecker = NewAPIAccessChecker(client.AuthorizationV1().SelfSubjectAccessReviews())
	w.namespaceValidator = NewNamespaceValidator(client.CoreV1().Namespaces())
	w.resourceResolver = NewResourceResolver(client.Discovery(), mapper)
	return nil
}

// Validate makes sure provided values for WhoCanOptions are valid.
func (w *whoCan) Validate() error {
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

	w.apiResource, err = w.resourceResolver.Resolve(w.verb, w.resource, w.subResource)
	if err != nil {
		return fmt.Errorf("resolving resource: %v", err)
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
	w.printAPIAccessWarnings(os.Stdout, warnings)

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

		nsList, err := w.namespaces.List(meta.ListOptions{})
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

func (w *whoCan) printAPIAccessWarnings(out io.Writer, warnings []string) {
	if len(warnings) > 0 {
		_, _ = fmt.Fprintln(out, "Warning: The list might not be complete due to missing permission(s):")
		for _, warning := range warnings {
			_, _ = fmt.Fprintf(out, "\t%s\n", warning)
		}
		_, _ = fmt.Fprintln(out)
	}
}

func (w *whoCan) getRoles() error {
	rl, err := w.rbac.Roles(w.namespace).List(meta.ListOptions{})
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
	crl, err := w.rbac.ClusterRoles().List(meta.ListOptions{})
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
		if resource == rbac.ResourceAll || resource == w.apiResource.Name {
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

func (w *whoCan) getRoleBindings() (roleBindings []rbac.RoleBinding, err error) {
	rbl, err := w.rbac.RoleBindings(w.namespace).List(meta.ListOptions{})
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
	rbl, err := w.rbac.ClusterRoleBindings().List(meta.ListOptions{})
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
	wr.Init(os.Stdout, 0, 8, 2, ' ', 0)

	resourceName := ""
	if w.resourceName != "" {
		resourceName = " " + w.resourceName
	}

	if len(roleBindings) == 0 {
		fmt.Printf("No subjects found with permissions to %s %s%s assigned through RoleBindings\n", w.verb, w.resource, resourceName)
	} else {
		fmt.Fprintln(wr, "ROLEBINDING\tNAMESPACE\tSUBJECT\tTYPE\tSA-NAMESPACE")
		for _, rb := range roleBindings {
			for _, s := range rb.Subjects {
				fmt.Fprintf(wr, "%s\t%s\t%s\t%s\t%s\n", rb.Name, rb.GetNamespace(), s.Name, s.Kind, s.Namespace)
			}
		}
	}

	fmt.Fprintln(wr)

	if len(clusterRoleBindings) == 0 {
		fmt.Printf("No subjects found with permissions to %s %s%s assigned through ClusterRoleBindings\n", w.verb, w.resource, resourceName)
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
