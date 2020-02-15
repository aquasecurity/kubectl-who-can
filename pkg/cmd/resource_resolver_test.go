package cmd

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	apismeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
)

type mapperMock struct {
	meta.DefaultRESTMapper
	mock.Mock
}

func (mm *mapperMock) ResourceFor(resource schema.GroupVersionResource) (schema.GroupVersionResource, error) {
	args := mm.Called(resource)
	return args.Get(0).(schema.GroupVersionResource), args.Error(1)
}

func TestResourceResolver_Resolve(t *testing.T) {

	podsGVR := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	podsGR := schema.GroupResource{Resource: "pods"}
	deploymentsGVR := schema.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "deployments"}
	deploymentsGR := schema.GroupResource{Group: "extensions", Resource: "deployments"}

	client := fake.NewSimpleClientset()

	client.Resources = []*apismeta.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []apismeta.APIResource{
				{Group: "", Version: "v1", Name: "pods", ShortNames: []string{"po"}, Verbs: []string{"list", "create", "delete"}},
				{Group: "", Version: "v1", Name: "pods/log", ShortNames: []string{}, Verbs: []string{"get"}},
				{Group: "", Version: "v1", Name: "services", ShortNames: []string{"svc"}, Verbs: []string{"list", "delete"}},
			},
		},
		{
			GroupVersion: "extensions/v1beta1",
			APIResources: []apismeta.APIResource{
				{Group: "extensions", Version: "v1beta1", Name: "deployments", Verbs: []string{"list", "get"}},
				{Group: "extensions", Version: "v1beta1", Name: "deployments/scale", Verbs: []string{"update", "patch"}},
			},
		},
	}

	type mappingResult struct {
		argGVR schema.GroupVersionResource

		returnGVR   schema.GroupVersionResource
		returnError error
	}

	type expected struct {
		gr  schema.GroupResource
		err error
	}

	data := []struct {
		scenario      string
		action        Action
		mappingResult *mappingResult
		expected
	}{
		{
			scenario: "A",
			action:   Action{Verb: "list", Resource: "pods"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "pods"},
				returnGVR: podsGVR,
			},
			expected: expected{gr: podsGR},
		},
		{
			scenario: "B",
			action:   Action{Verb: "list", Resource: "po"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "po"},
				returnGVR: podsGVR,
			},
			expected: expected{gr: podsGR},
		},
		{
			scenario: "C",
			action:   Action{Verb: "eat", Resource: "pods"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "pods"},
				returnGVR: podsGVR,
			},
			expected: expected{err: errors.New("the \"pods\" resource does not support the \"eat\" verb, only [list create delete]")},
		},
		{
			scenario: "D",
			action:   Action{Verb: "list", Resource: "deployments.extensions"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Group: "extensions", Version: "", Resource: "deployments"},
				returnGVR: deploymentsGVR,
			},
			expected: expected{gr: deploymentsGR},
		},
		{
			scenario: "E",
			action:   Action{Verb: "get", Resource: "pods", SubResource: "log"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "pods"},
				returnGVR: podsGVR,
			},
			expected: expected{gr: podsGR},
		},
		{
			scenario: "F",
			action:   Action{Verb: "get", Resource: "pods", SubResource: "logz"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "pods"},
				returnGVR: podsGVR,
			},
			expected: expected{err: errors.New("the server doesn't have a resource type \"pods/logz\"")},
		},
		{
			scenario: "G",
			action:   Action{Verb: "list", Resource: "bees"},
			mappingResult: &mappingResult{
				argGVR:      schema.GroupVersionResource{Resource: "bees"},
				returnError: errors.New("mapping failed"),
			},
			expected: expected{err: errors.New("the server doesn't have a resource type \"bees\"")},
		},
		{
			scenario: "H",
			action:   Action{Verb: rbac.VerbAll, Resource: "pods"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "pods"},
				returnGVR: podsGVR,
			},
			expected: expected{gr: podsGR},
		},
		{
			scenario: "I",
			action:   Action{Verb: "list", Resource: rbac.ResourceAll},
			expected: expected{gr: schema.GroupResource{Resource: rbac.ResourceAll}},
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			mapper := new(mapperMock)

			if tt.mappingResult != nil {
				mapper.On("ResourceFor", tt.mappingResult.argGVR).
					Return(tt.mappingResult.returnGVR, tt.mappingResult.returnError)
			}

			resolver := NewResourceResolver(client.Discovery(), mapper)

			resource, err := resolver.Resolve(tt.action.Verb, tt.action.Resource, tt.action.SubResource)

			assert.Equal(t, tt.expected.err, err)
			assert.Equal(t, tt.expected.gr, resource)

			mapper.AssertExpectations(t)
		})
	}
}
