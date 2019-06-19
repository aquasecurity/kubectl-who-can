package cmd

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	client := fake.NewSimpleClientset()

	client.Resources = []*v1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []v1.APIResource{
				{Version: "v1", Name: "pods", ShortNames: []string{"po"}, Verbs: []string{"list", "create", "delete"}},
				{Version: "v1", Name: "pods/log", ShortNames: []string{}, Verbs: []string{"get"}},
				{Version: "v1", Name: "services", ShortNames: []string{"svc"}, Verbs: []string{"list", "delete"}},
			},
		},
	}

	type given struct {
		verb        string
		resource    string
		subResource string
	}

	type mappingResult struct {
		out string
		err error
	}

	type expected struct {
		resource string
		err      error
	}

	data := []struct {
		scenario string
		given
		*mappingResult
		expected
	}{
		{
			scenario: "A",
			given:    given{verb: "list", resource: "pods"},
			expected: expected{resource: "pods"},
		},
		{
			scenario: "B",
			given:    given{verb: "list", resource: "po"},
			expected: expected{resource: "pods"},
		},
		{
			scenario: "C",
			given:    given{verb: "eat", resource: "pods"},
			expected: expected{err: errors.New("the \"pods\" resource does not support the \"eat\" verb, only [list create delete]")},
		},
		{
			scenario: "D",
			given:    given{verb: "list", resource: "services"},
			expected: expected{resource: "services"},
		},
		{
			scenario: "E",
			given:    given{verb: "list", resource: "svc"},
			expected: expected{resource: "services"},
		},
		{
			scenario: "F",
			given:    given{verb: "mow", resource: "services"},
			expected: expected{err: errors.New("the \"services\" resource does not support the \"mow\" verb, only [list delete]")},
		},
		{
			scenario: "G",
			given:    given{verb: "get", resource: "pods", subResource: "log"},
			expected: expected{resource: "pods/log"},
		},
		{
			scenario: "H",
			given:    given{verb: "get", resource: "pods", subResource: "logz"},
			expected: expected{err: errors.New("the server doesn't have a resource type \"pods/logz\"")},
		},
		{
			scenario:      "I",
			given:         given{verb: "list", resource: "pod"},
			mappingResult: &mappingResult{out: "pods"},
			expected:      expected{resource: "pods"},
		},
		{
			scenario:      "J",
			given:         given{verb: "get", resource: "pod", subResource: "log"},
			mappingResult: &mappingResult{out: "pods"},
			expected:      expected{resource: "pods/log"},
		},
		{
			scenario:      "K",
			given:         given{verb: "list", resource: "pod"},
			mappingResult: &mappingResult{err: errors.New("mapping failed")},
			expected:      expected{err: errors.New("the server doesn't have a resource type \"pod\"")},
		},
	}

	for _, tt := range data {
		t.Run(tt.scenario, func(t *testing.T) {
			mapper := new(mapperMock)
			if tt.mappingResult != nil {
				mapper.On("ResourceFor", schema.GroupVersionResource{Resource: tt.given.resource}).
					Return(schema.GroupVersionResource{Resource: tt.mappingResult.out}, tt.mappingResult.err)
			}

			resolver := NewResourceResolver(client.Discovery(), mapper)

			resource, err := resolver.Resolve(tt.given.verb, tt.given.resource, tt.given.subResource)

			assert.Equal(t, tt.expected.err, err)
			assert.Equal(t, resource.Name, tt.expected.resource)

			mapper.AssertExpectations(t)
		})
	}
}
