package cmd

import (
	"fmt"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	apismeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/klog/v2"
	"strings"
)

// ResourceResolver wraps the Resolve method.
//
// Resolve attempts to resolve a GroupResource by `resource` and `subResource`.
// It also validates that the specified `verb` is supported by the resolved resource.
type ResourceResolver interface {
	Resolve(verb, resource, subResource string) (schema.GroupResource, error)
}

type resourceResolver struct {
	client discovery.DiscoveryInterface
	mapper meta.RESTMapper
}

// NewResourceResolver constructs the default ResourceResolver.
func NewResourceResolver(client discovery.DiscoveryInterface, mapper meta.RESTMapper) ResourceResolver {
	return &resourceResolver{
		client: client,
		mapper: mapper,
	}
}

func (rv *resourceResolver) Resolve(verb, resource, subResource string) (schema.GroupResource, error) {
	if resource == rbac.ResourceAll {
		return schema.GroupResource{Resource: resource}, nil
	}

	name := resource
	if subResource != "" {
		name = name + "/" + subResource
	}

	gvr, err := rv.resolveGVR(resource)
	if err != nil {
		klog.V(3).Infof("Error while resolving GVR for resource %s: %v", resource, err)
		return schema.GroupResource{}, fmt.Errorf("the server doesn't have a resource type \"%s\"", name)
	}

	apiResource, err := rv.resolveAPIResource(gvr, subResource)
	if err != nil {
		klog.V(3).Infof("Error while resolving APIResource for GVR %v and subResource %s: %v", gvr, subResource, err)
		return schema.GroupResource{}, fmt.Errorf("the server doesn't have a resource type \"%s\"", name)
	}

	if !rv.isVerbSupportedBy(verb, apiResource) {
		return schema.GroupResource{}, fmt.Errorf("the \"%s\" resource does not support the \"%s\" verb, only %v", apiResource.Name, verb, apiResource.Verbs)
	}

	return gvr.GroupResource(), nil
}

func (rv *resourceResolver) resolveGVR(resource string) (schema.GroupVersionResource, error) {
	if resource == rbac.ResourceAll {
		return schema.GroupVersionResource{Resource: resource}, nil
	}

	fullySpecifiedGVR, groupResource := schema.ParseResourceArg(strings.ToLower(resource))
	gvr := schema.GroupVersionResource{}
	if fullySpecifiedGVR != nil {
		gvr, _ = rv.mapper.ResourceFor(*fullySpecifiedGVR)
	}

	if gvr.Empty() {
		var err error
		gvr, err = rv.mapper.ResourceFor(groupResource.WithVersion(""))
		if err != nil {
			return schema.GroupVersionResource{}, err
		}
	}

	return gvr, nil
}

func (rv *resourceResolver) resolveAPIResource(gvr schema.GroupVersionResource, subResource string) (apismeta.APIResource, error) {
	index, err := rv.indexResources(gvr)
	if err != nil {
		return apismeta.APIResource{}, err
	}

	apiResource, err := rv.lookupResource(index, gvr.Resource)
	if err != nil {
		return apismeta.APIResource{}, err
	}

	if subResource != "" {
		apiResource, err = rv.lookupSubResource(index, apiResource.Name+"/"+subResource)
		if err != nil {
			return apismeta.APIResource{}, err
		}
	}
	return apiResource, nil
}

func (rv *resourceResolver) lookupResource(index map[string]apismeta.APIResource, resourceArg string) (apismeta.APIResource, error) {
	apiResource, ok := index[resourceArg]
	if ok {
		return apiResource, nil
	}

	return apismeta.APIResource{}, fmt.Errorf("not found \"%s\"", resourceArg)
}

func (rv *resourceResolver) lookupSubResource(index map[string]apismeta.APIResource, subResource string) (apismeta.APIResource, error) {
	apiResource, ok := index[subResource]
	if !ok {
		return apismeta.APIResource{}, fmt.Errorf("not found \"%s\"", subResource)
	}
	return apiResource, nil
}

// indexResources builds a lookup index for APIResources where the keys are plural resources names.
// NB A subresource is also represented by APIResource and the corresponding key is <resource>/<subresource>,
// for example, `pods/log` or `deployments/scale`.
func (rv *resourceResolver) indexResources(gvr schema.GroupVersionResource) (map[string]apismeta.APIResource, error) {
	index := make(map[string]apismeta.APIResource)

	resourceList, err := rv.client.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
	if err != nil {
		return nil, fmt.Errorf("getting API groups: %v", err)
	}
	for _, res := range resourceList.APIResources {
		index[res.Name] = res
	}

	return index, nil
}

// isVerbSupportedBy returns `true` if the given verb is supported by the given resource, `false` otherwise.
// Returns `true` if the given verb equals VerbAll.
func (rv *resourceResolver) isVerbSupportedBy(verb string, resource apismeta.APIResource) bool {
	if verb == rbac.VerbAll {
		return true
	}
	if resource.Name == "podsecuritypolicies" && verb == "use" {
		return true
	}
	supported := false
	for _, v := range resource.Verbs {
		if v == verb {
			supported = true
		}
	}
	return supported
}
