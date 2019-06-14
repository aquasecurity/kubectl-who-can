package cmd

import (
	"fmt"
	"github.com/aquasecurity/kubectl-who-can/pkg/cmd/whocan"
	"io"
	clientcore "k8s.io/client-go/kubernetes/typed/core/v1"
	clientrbac "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"os"
	"text/tabwriter"

	"github.com/golang/glog"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
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
	namespace    string

	namespaces         clientcore.NamespaceInterface
	rbac               clientrbac.RbacV1Interface
	namespaceValidator whocan.NamespaceValidator
	resourceResolver   whocan.ResourceResolver
	accessChecker      whocan.APIAccessChecker

	r           roles
	apiResource meta.APIResource
}

func (w *whoCan) do() error {
	warnings, err := w.checkAPIAccess()
	if err != nil {
		return fmt.Errorf("checking API access: %v", err)
	}

	err = w.namespaceValidator.Validate(w.namespace)
	if err != nil {
		return fmt.Errorf("validating namespace: %v", err)
	}

	w.apiResource, err = w.resourceResolver.Resolve(w.verb, w.resource)
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
