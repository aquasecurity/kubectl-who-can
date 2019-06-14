package cmd

import (
	"errors"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
)

func TestResourceResolver_Resolve(t *testing.T) {

	client := fake.NewSimpleClientset()

	client.Resources = []*v1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []v1.APIResource{
				{Name: "pods", ShortNames: []string{"po"}, Verbs: []string{"list", "create", "delete"}},
				{Name: "services", ShortNames: []string{"svc"}, Verbs: []string{"list", "delete"}},
			},
		},
	}

	data := []struct {
		name        string
		verbArg     string
		resourceArg string

		expectedResourceName string
		expectedErr          error
	}{
		{name: "s1", verbArg: "list", resourceArg: "pods",
			expectedResourceName: "pods"},
		{name: "s2", verbArg: "list", resourceArg: "po",
			expectedResourceName: "pods"},
		{name: "s3", verbArg: "eat", resourceArg: "pods",
			expectedResourceName: "", expectedErr: errors.New("the \"pods\" resource does not support the \"eat\" verb, only [list create delete]")},
		{name: "s4", verbArg: "list", resourceArg: "services",
			expectedResourceName: "services"},
		{name: "s5", verbArg: "list", resourceArg: "svc",
			expectedResourceName: "services"},
		{name: "s6", verbArg: "mow", resourceArg: "services",
			expectedResourceName: "", expectedErr: errors.New("the \"services\" resource does not support the \"mow\" verb, only [list delete]")},
	}

	resolver := NewResourceResolver(client.Discovery())

	for _, tt := range data {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := resolver.Resolve(tt.verbArg, tt.resourceArg)

			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, resource.Name, tt.expectedResourceName)
		})
	}
}
