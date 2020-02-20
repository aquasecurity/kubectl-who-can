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
	pspGVR := schema.GroupVersionResource{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies"}
	pspGV := schema.GroupResource{Group: "policy", Resource: "podsecuritypolicies"}

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
		{
			GroupVersion: "policy/v1beta1",
			APIResources: []apismeta.APIResource{
				{Group: "policy", Version: "v1beta1", Name: "podsecuritypolicies", Verbs: []string{"list", "get"}},
			},
		},
	}

	type mappingResult struct {
		argGVR schema.GroupVersionResource

		returnGVR   schema.GroupVersionResource
		returnError error
	}

	testCases := []struct {
		name          string
		action        Action
		mappingResult *mappingResult
		expectedGR    schema.GroupResource
		expectedError error
	}{
		{
			name:   "A",
			action: Action{Verb: "list", Resource: "pods"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "pods"},
				returnGVR: podsGVR,
			},
			expectedGR: podsGR,
		},
		{
			name:   "B",
			action: Action{Verb: "list", Resource: "po"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "po"},
				returnGVR: podsGVR,
			},
			expectedGR: podsGR,
		},
		{
			name:   "C",
			action: Action{Verb: "eat", Resource: "pods"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "pods"},
				returnGVR: podsGVR,
			},
			expectedError: errors.New("the \"pods\" resource does not support the \"eat\" verb, only [list create delete]"),
		},
		{
			name:   "D",
			action: Action{Verb: "list", Resource: "deployments.extensions"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Group: "extensions", Version: "", Resource: "deployments"},
				returnGVR: deploymentsGVR,
			},
			expectedGR: deploymentsGR,
		},
		{
			name:   "E",
			action: Action{Verb: "get", Resource: "pods", SubResource: "log"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "pods"},
				returnGVR: podsGVR,
			},
			expectedGR: podsGR,
		},
		{
			name:   "F",
			action: Action{Verb: "get", Resource: "pods", SubResource: "logz"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "pods"},
				returnGVR: podsGVR,
			},
			expectedError: errors.New("the server doesn't have a resource type \"pods/logz\""),
		},
		{
			name:   "G",
			action: Action{Verb: "list", Resource: "bees"},
			mappingResult: &mappingResult{
				argGVR:      schema.GroupVersionResource{Resource: "bees"},
				returnError: errors.New("mapping failed"),
			},
			expectedError: errors.New("the server doesn't have a resource type \"bees\""),
		},
		{
			name:   "H",
			action: Action{Verb: rbac.VerbAll, Resource: "pods"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "pods"},
				returnGVR: podsGVR,
			},
			expectedGR: podsGR,
		},
		{
			name:       "I",
			action:     Action{Verb: "list", Resource: rbac.ResourceAll},
			expectedGR: schema.GroupResource{Resource: rbac.ResourceAll},
		},
		{
			name:   "Should resolve psp",
			action: Action{Verb: "use", Resource: "psp"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "psp"},
				returnGVR: pspGVR,
			},
			expectedGR: pspGV,
		},
		{
			name:   "Should return error when psp verb is not supported",
			action: Action{Verb: "cook", Resource: "psp"},
			mappingResult: &mappingResult{
				argGVR:    schema.GroupVersionResource{Resource: "psp"},
				returnGVR: pspGVR,
			},
			expectedError: errors.New("the \"podsecuritypolicies\" resource does not support the \"cook\" verb, only [list get]"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mapper := new(mapperMock)

			if tc.mappingResult != nil {
				mapper.On("ResourceFor", tc.mappingResult.argGVR).
					Return(tc.mappingResult.returnGVR, tc.mappingResult.returnError)
			}

			resolver := NewResourceResolver(client.Discovery(), mapper)

			resource, err := resolver.Resolve(tc.action.Verb, tc.action.Resource, tc.action.SubResource)

			assert.Equal(t, tc.expectedError, err)
			assert.Equal(t, tc.expectedGR, resource)

			mapper.AssertExpectations(t)
		})
	}
}
