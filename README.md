# kubectl-who-can
[WIP] show who has permissions to &lt;verb> &lt;resources> in kubernetes

[![asciicast](https://asciinema.org/a/ccqqYwA5L5rMV9kd1tgzyZJ2j.svg)](https://asciinema.org/a/ccqqYwA5L5rMV9kd1tgzyZJ2j)

## TODO

* Filter by namespace
* Specify a particular object e.g. who-can use pod-security-policy <name>
* Make it a kubectl plugin (for now it's a standalone executable)
* Alert if user doesn't have access to all namespaces, roles, clusterroles or bindings (as info won't be complete)
