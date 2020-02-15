package cmd

import (
	"github.com/stretchr/testify/mock"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type resourceResolverMock struct {
	mock.Mock
}

func (r *resourceResolverMock) Resolve(verb, resource, subResource string) (schema.GroupResource, error) {
	args := r.Called(verb, resource, subResource)
	return args.Get(0).(schema.GroupResource), args.Error(1)
}
