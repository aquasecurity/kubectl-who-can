package cmd

import (
	"fmt"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

// ResourceResolver wraps the Resolve method.
//
// Resolve attempts to resolve an APIResource by `resource` and `subResource`.
// It then validates that the specified `verb` is supported.
// The returned APIResource may represent a resource (e.g. pods) or a sub-resource (e.g. pods/log).
type ResourceResolver interface {
	Resolve(verb, resource, subResource string) (v1.APIResource, error)
}

type resourceResolver struct {
	client discovery.DiscoveryInterface
	mapper meta.RESTMapper
}

func NewResourceResolver(client discovery.DiscoveryInterface, mapper meta.RESTMapper) ResourceResolver {
	return &resourceResolver{
		client: client,
		mapper: mapper,
	}
}

func (rv *resourceResolver) Resolve(verbArg, resourceArg, subResource string) (v1.APIResource, error) {
	resource, err := rv.resourceFor(resourceArg, subResource)
	if err != nil {
		name := resourceArg
		if subResource != "" {
			name = name + "/" + subResource
		}
		return v1.APIResource{}, fmt.Errorf("the server doesn't have a resource type \"%s\"", name)
	}

	if !rv.isVerbSupportedBy(verbArg, resource) {
		return v1.APIResource{}, fmt.Errorf("the \"%s\" resource does not support the \"%s\" verb, only %v", resource.Name, verbArg, resource.Verbs)
	}

	return resource, nil
}

func (rv *resourceResolver) resourceFor(resourceArg, subResource string) (v1.APIResource, error) {
	index, err := rv.indexResources()
	if err != nil {
		return v1.APIResource{}, err
	}

	apiResource, err := rv.lookupResource(index, resourceArg)
	if err != nil {
		return v1.APIResource{}, err
	}

	if subResource != "" {
		apiResource, err = rv.lookupSubResource(index, apiResource.Name+"/"+subResource)
		if err != nil {
			return v1.APIResource{}, err
		}
		return apiResource, nil
	}
	return apiResource, nil
}

func (rv *resourceResolver) lookupResource(index map[string]v1.APIResource, resourceArg string) (v1.APIResource, error) {
	resource, ok := index[resourceArg]
	if ok {
		return resource, nil
	}

	gvr, err := rv.mapper.ResourceFor(schema.GroupVersionResource{Resource: resourceArg})
	if err != nil {
		return v1.APIResource{}, err
	}
	resource, ok = index[gvr.Resource]
	if ok {
		return resource, nil
	}
	return v1.APIResource{}, fmt.Errorf("not found \"%s\"", resourceArg)
}

func (rv *resourceResolver) lookupSubResource(index map[string]v1.APIResource, subResource string) (v1.APIResource, error) {
	apiResource, ok := index[subResource]
	if !ok {
		return v1.APIResource{}, fmt.Errorf("not found \"%s\"", subResource)
	}
	return apiResource, nil
}

// indexResources builds a lookup index for APIResources where the keys are resources names (both plural and short names).
func (rv *resourceResolver) indexResources() (map[string]v1.APIResource, error) {
	serverResources := make(map[string]v1.APIResource)

	serverGroups, err := rv.client.ServerGroups()
	if err != nil {
		return nil, fmt.Errorf("getting API groups: %v", err)
	}
	for _, sg := range serverGroups.Groups {
		for _, version := range sg.Versions {
			// Consider only preferred versions
			if version.GroupVersion != sg.PreferredVersion.GroupVersion {
				continue
			}
			rsList, err := rv.client.ServerResourcesForGroupVersion(version.GroupVersion)
			if err != nil {
				return nil, fmt.Errorf("getting resources for API group: %v", err)
			}

			for _, res := range rsList.APIResources {
				serverResources[res.Name] = res
				if len(res.ShortNames) > 0 {
					for _, sn := range res.ShortNames {
						serverResources[sn] = res
					}
				}
			}
		}
	}
	return serverResources, nil
}

// isVerbSupportedBy returns `true` if the given verb is supported by the given resource, `false` otherwise.
func (rv *resourceResolver) isVerbSupportedBy(verb string, resource v1.APIResource) bool {
	supported := false
	for _, v := range resource.Verbs {
		if v == verb {
			supported = true
		}
	}
	return supported
}
