# kubectl-who-can
[WIP] show who has permissions to &lt;verb> &lt;resources> in kubernetes

## TODO

* Filter by namespace
* Specify a particular object e.g. who-can use pod-security-policy <name>
* Make it a kubectl plugin (for now it's a standalone executable)
* Alert if user doesn't have access to all namespaces, roles, clusterroles or bindings (as info won't be complete)
