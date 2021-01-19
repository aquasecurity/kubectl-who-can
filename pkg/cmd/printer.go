package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	rbac "k8s.io/api/rbac/v1"
)

// Printer formats and prints check results and warnings.
type Printer struct {
	out  io.Writer
	wide bool
}

// NewPrinter constructs a new Printer with the specified output io.Writer
// and output format.
func NewPrinter(out io.Writer, wide bool) *Printer {
	return &Printer{
		out:  out,
		wide: wide,
	}
}

// Struct to hold either rb or crb objects
type rowData struct {
	Name     string         `json:"name"`
	RoleRef  rbac.RoleRef   `json:"roleRef" protobuf:"bytes,3,opt,name=roleRef"`
	Subjects []rbac.Subject `json:"subjects,omitempty" protobuf:"bytes,2,rep,name=subjects"`
}

// ExportData exports data to a file.
func (p *Printer) ExportData(action Action, roleBindings []rbac.RoleBinding, clusterRoleBindings []rbac.ClusterRoleBinding) {
	// Final data to be exported as JSON
	data := make(map[string]interface{}, 0)

	if action.Resource != "" {
		// NonResourceURL permissions can only be granted through ClusterRoles. Hence no point in printing RoleBindings section.
		if len(roleBindings) != 0 {
			rbData := []rowData{}
			// Get required data from each roleBinding
			for _, rb := range roleBindings {
				rbData = append(rbData, rowData{rb.Name, rb.RoleRef, rb.Subjects})
			}
			data["roleBindings"] = rbData
		}
	}

	if len(clusterRoleBindings) != 0 {
		crbData := []rowData{}
		// Get required data from each roleBinding
		for _, crb := range clusterRoleBindings {
			crbData = append(crbData, rowData{crb.Name, crb.RoleRef, crb.Subjects})
		}
		data["clusterRoleBindings"] = crbData
	}

	// Write data into output stream
	encoder := json.NewEncoder(p.out)
	encoder.Encode(data)
}

func (p *Printer) PrintChecks(action Action, roleBindings []rbac.RoleBinding, clusterRoleBindings []rbac.ClusterRoleBinding) {
	wr := new(tabwriter.Writer)
	wr.Init(p.out, 0, 8, 2, ' ', 0)

	if action.Resource != "" {
		// NonResourceURL permissions can only be granted through ClusterRoles. Hence no point in printing RoleBindings section.
		if len(roleBindings) == 0 {
			_, _ = fmt.Fprintf(p.out, "No subjects found with permissions to %s assigned through RoleBindings\n", action)
		} else {
			p.printBindingsHeader(wr)
			for _, rb := range roleBindings {
				for _, s := range rb.Subjects {
					p.printBindingRow(wr, rb, s)
				}
			}
		}

		_, _ = fmt.Fprintln(wr)
	}

	if len(clusterRoleBindings) == 0 {
		_, _ = fmt.Fprintf(p.out, "No subjects found with permissions to %s assigned through ClusterRoleBindings\n", action)
	} else {
		p.printClusterBindingsHeader(wr)
		for _, rb := range clusterRoleBindings {
			for _, s := range rb.Subjects {
				p.printClusterBindingRow(wr, rb, s)
			}
		}
	}
	_ = wr.Flush()
}

func (p *Printer) printBindingsHeader(wr *tabwriter.Writer) {
	var columns []string
	if p.wide {
		columns = []string{"ROLEBINDING", "ROLE", "NAMESPACE", "SUBJECT", "TYPE", "SA-NAMESPACE"}
	} else {
		columns = []string{"ROLEBINDING", "NAMESPACE", "SUBJECT", "TYPE", "SA-NAMESPACE"}
	}
	_, _ = fmt.Fprintln(wr, strings.Join(columns, "\t"))
}

func (p *Printer) printBindingRow(wr *tabwriter.Writer, rb rbac.RoleBinding, s rbac.Subject) {
	var format string
	var args []interface{}

	if p.wide {
		format = "%s\t%s/%s\t%s\t%s\t%s\t%s\n"
		args = []interface{}{rb.Name, rb.RoleRef.Kind, rb.RoleRef.Name, rb.Namespace, s.Name, s.Kind, s.Namespace}
	} else {
		format = "%s\t%s\t%s\t%s\t%s\n"
		args = []interface{}{rb.Name, rb.Namespace, s.Name, s.Kind, s.Namespace}
	}
	_, _ = fmt.Fprintf(wr, format, args...)
}

func (p *Printer) printClusterBindingsHeader(wr *tabwriter.Writer) {
	var columns []string
	if p.wide {
		columns = []string{"CLUSTERROLEBINDING", "ROLE", "SUBJECT", "TYPE", "SA-NAMESPACE"}
	} else {
		columns = []string{"CLUSTERROLEBINDING", "SUBJECT", "TYPE", "SA-NAMESPACE"}
	}
	_, _ = fmt.Fprintln(wr, strings.Join(columns, "\t"))
}

func (p *Printer) printClusterBindingRow(wr *tabwriter.Writer, crb rbac.ClusterRoleBinding, s rbac.Subject) {
	var format string
	var args []interface{}
	if p.wide {
		format = "%s\t%s/%s\t%s\t%s\t%s\n"
		args = []interface{}{crb.Name, crb.RoleRef.Kind, crb.RoleRef.Name, s.Name, s.Kind, s.Namespace}
	} else {
		format = "%s\t%s\t%s\t%s\n"
		args = []interface{}{crb.Name, s.Name, s.Kind, s.Namespace}
	}
	_, _ = fmt.Fprintf(wr, format, args...)
}

// PrintWarnings prints warnings, if any, returned by CheckAPIAccess.
func (p *Printer) PrintWarnings(warnings []string) {
	if len(warnings) > 0 {
		_, _ = fmt.Fprintln(p.out, "Warning: The list might not be complete due to missing permission(s):")
		for _, warning := range warnings {
			_, _ = fmt.Fprintf(p.out, "\t%s\n", warning)
		}
		_, _ = fmt.Fprintln(p.out)
	}
}
