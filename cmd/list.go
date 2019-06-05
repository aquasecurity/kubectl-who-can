package cmd

import (
	"fmt"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"os"
	"text/tabwriter"

	"github.com/golang/glog"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	client       kubernetes.Interface
	r            roles
}

func (w *whoCan) validateNamespace(name string) error {

	if name != v1.NamespaceAll {
		ns, err := w.client.CoreV1().Namespaces().Get(name, metav1.GetOptions{})
		if err != nil {
			if statusErr, ok := err.(*errors.StatusError); ok &&
				statusErr.Status().Reason == metav1.StatusReasonNotFound {
				return fmt.Errorf("not found")
			}
			return fmt.Errorf("getting namespace: %v", err)
		}
		if ns.Status.Phase != v1.NamespaceActive {
			return fmt.Errorf("invalid status: %v", ns.Status.Phase)
		}
	}
	return nil
}

func (w *whoCan) do() error {
	err := w.validateNamespace(namespace)
	if err != nil {
		return fmt.Errorf("validating namespace: %s: %v", namespace, err)
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

	// Output the results
	w.output(roleBindings, clusterRoleBindings)

	// TODO!! Check the user's own permissions to see if we might be missing something in the output
	return nil
}

func (w *whoCan) getRoles() error {
	rl, err := w.client.RbacV1().Roles(namespace).List(metav1.ListOptions{})
	if err != nil {
		return err
	}

	w.filterRoles(rl)
	return nil
}

func (w *whoCan) filterRoles(roles *rbacv1.RoleList) {
	for _, item := range roles.Items {
		for _, rule := range item.Rules {
			if !w.policyMatches(rule) {
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
	crl, err := w.client.RbacV1().ClusterRoles().List(metav1.ListOptions{})
	if err != nil {
		return err
	}

	w.filterClusterRoles(crl)
	return nil
}

func (w *whoCan) filterClusterRoles(roles *rbacv1.ClusterRoleList) {
	for _, item := range roles.Items {
		for _, rule := range item.Rules {
			if !w.policyMatches(rule) {
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

func (w *whoCan) policyMatches(rule rbacv1.PolicyRule) bool {
	return w.matchesVerb(rule) &&
		w.matchesResource(rule) &&
		w.matchesResourceName(rule)
}

func (w *whoCan) matchesVerb(rule rbacv1.PolicyRule) bool {
	for _, verb := range rule.Verbs {
		if verb == rbacv1.VerbAll || verb == w.verb {
			return true
		}
	}
	return false
}

func (w *whoCan) matchesResource(rule rbacv1.PolicyRule) bool {
	for _, resource := range rule.Resources {
		if resource == rbacv1.ResourceAll || resource == w.resource {
			return true
		}
	}
	return false
}

func (w *whoCan) matchesResourceName(rule rbacv1.PolicyRule) bool {
	if w.resourceName == "" {
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

func (w *whoCan) getRoleBindings() (roleBindings []rbacv1.RoleBinding, err error) {
	rbl, err := w.client.RbacV1().RoleBindings(namespace).List(metav1.ListOptions{})
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

func (w *whoCan) getClusterRoleBindings() (clusterRoleBindings []rbacv1.ClusterRoleBinding, err error) {
	rbl, err := w.client.RbacV1().ClusterRoleBindings().List(metav1.ListOptions{})
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

func (r roles) match(roleRef *rbacv1.RoleRef) bool {
	tempRole := role{
		name:          roleRef.Name,
		isClusterRole: (roleRef.Kind == "ClusterRole"),
	}

	glog.V(3).Info(fmt.Sprintf("Testing against roleRef: %v", tempRole))

	_, ok := r[tempRole]
	return ok
}

func (w *whoCan) output(roleBindings []rbacv1.RoleBinding, clusterRoleBindings []rbacv1.ClusterRoleBinding) {
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
