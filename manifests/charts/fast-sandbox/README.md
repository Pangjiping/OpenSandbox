# fast-sandbox Helm Chart

A Helm chart for deploying the fast-sandbox Firecracker chain on a Kubernetes cluster: the `sandbox.fast.io` all-in-one control plane (reconcilers + FastPath gRPC), the sandbox proxy, the janitor, and the node-side runtime pieces (Firecracker asset installer and the firecracker runtime-agent with DART peer discovery).

## Introduction

The chart deploys:

- **fast-sandbox-controller** (Deployment + `fast-sandbox-fastpath` Service): one process running the `sandbox.fast.io` reconcilers and the FastPath gRPC API (development topology, no leader election)
- **fast-sandbox-proxy** (Deployment + Service): signed-route aware data-plane proxy
- **fast-sandbox-janitor** (DaemonSet): per-node orphaned fastlet cleanup
- **firecracker-runtime-installer** (DaemonSet): installs the pinned Firecracker release (binary + jailer) and the guest kernel on every Firecracker-capable node
- **firecracker-runtime-agent** (DaemonSet + `dart` headless Service): node-level UDS management API used by fastlet Firecracker drivers, with a node-local DART child for P2P artifact delivery

boxlite and other non-Firecracker runtimes are out of scope for the images this chart expects (see `manifests/release/build-fast-sandbox.sh`).

## Prerequisites

- Kubernetes 1.21.1+
- Helm 3.0+
- The `sandbox.fast.io` CRDs and component RBAC, installed by the [base chart](../base) (`helm install base manifests/charts/base` from the repository root). Keep the namespace values in sync: `fastSandbox.namespaces.*` in base vs `systemNamespace` / `resourceNamespace` here.
- The companion images built from the source pinned in [`manifests/third-party/fast-sandbox.commit`](../third-party/fast-sandbox.commit):

  ```bash
  manifests/release/build-fast-sandbox.sh --load-kind <kind-cluster>
  ```

- Firecracker-capable (KVM) nodes labeled for the installer and agent DaemonSets:

  ```bash
  kubectl label node <node> fast-sandbox.io/firecracker-node=true
  ```

- The agent registry Secret with artifact-store pull credentials (compiled `registry.json`):

  ```bash
  kubectl -n fast-sandbox-system create secret generic fast-sandbox-agent-registry \
    --from-file=registry.json=<compiled-registry.json>
  ```

## Installing the Chart

```bash
helm install fast-sandbox manifests/charts/fast-sandbox
```

Or as part of the umbrella chart:

```bash
helm install opensandbox manifests/charts/opensandbox \
  --set fast-sandbox.enabled=true
```

## Parameters

The following table lists the configurable parameters of the chart and their default values.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| artifactStore.endpoint | string | `""` | S3-compatible endpoint (empty = AWS default) |
| artifactStore.store | string | `"s3://sandbox-images/publish"` | Store URI root for published artifacts (golden images, snapshots) |
| controller.enabled | bool | `true` | Whether the control plane Deployment + FastPath Service are installed |
| controller.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| controller.image.repository | string | `"fast-sandbox/controller"` | Controller image repository (built by manifests/release/build-fast-sandbox.sh) |
| controller.image.tag | string | `"dev"` | Image tag |
| controller.replicaCount | int | `1` | Number of controller replicas (no leader election; keep 1) |
| controller.resources | object | `{"limits":{"cpu":"1","memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}}` | Resource requests and limits for the controller |
| controller.sandboxtemplateBuilderImage | string | `"fast-sandbox/sandboxtemplate-builder:dev"` | Image that executes SandboxTemplate golden-image builds (builder Pods are created by the controller; build it with manifests/release/build-fast-sandbox.sh) |
| firecrackerInstaller.enabled | bool | `true` | Whether the installer DaemonSet is installed |
| firecrackerInstaller.fcVersion | string | `"v1.16.1"` | Firecracker release to install |
| firecrackerInstaller.kernelUrl | string | `"https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260722-38359b8055fc-0/x86_64/vmlinux-6.1.176"` | Guest kernel to install (Amazon microvm CI artifact with ACPI/VMGenID support) |
| firecrackerInstaller.nodeSelector | object | `{"fast-sandbox.io/firecracker-node":"true"}` | Node selector selecting the Firecracker-capable nodes |
| fullnameOverride | string | `""` | Override the full name of the chart |
| imagePullSecrets | list | `[]` | Image pull secrets for every workload in this chart |
| janitor.enabled | bool | `true` | Whether the janitor DaemonSet is installed |
| janitor.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| janitor.image.repository | string | `"fast-sandbox/janitor"` | Janitor image repository (built by manifests/release/build-fast-sandbox.sh) |
| janitor.image.tag | string | `"dev"` | Image tag |
| janitor.orphanTimeout | string | `"30s"` | Orphan timeout before cleanup |
| janitor.scanInterval | string | `"2m"` | Orphan scan interval |
| nameOverride | string | `""` | Override the name of the chart |
| proxy.enabled | bool | `true` | Whether the sandbox-proxy Deployment + Service are installed |
| proxy.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| proxy.image.repository | string | `"fast-sandbox/sandbox-proxy"` | Sandbox-proxy image repository (built by manifests/release/build-fast-sandbox.sh) |
| proxy.image.tag | string | `"dev"` | Image tag |
| proxy.replicaCount | int | `2` | Number of proxy replicas |
| proxy.resources | object | `{"limits":{"cpu":"1","memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}}` | Resource requests and limits for the proxy |
| resourceNamespace | string | `"fast-sandbox"` | Namespace for fast-sandbox resource objects (reserved for future use; workloads always run in systemNamespace). Must match base.fastSandbox.namespaces.resources. |
| routeKeys.create | bool | `true` | Specifies whether the fast-sandbox-route-keys Secret is created here |
| routeKeys.developmentOnly | bool | `true` | Mark the Secret with fast-sandbox.io/development-only (set false when provisioning real keys via privateKey/publicKey) |
| routeKeys.existingSecret | string | `""` | Use an existing Secret instead of creating one (its keys must be private-key / public-key) |
| routeKeys.privateKey | string | `"nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="` | Ed25519 private key (base64) used to sign f1.* gateway routes |
| routeKeys.publicKey | string | `"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="` | Ed25519 public key (base64) used to verify f1.* gateway routes |
| runtimeAgent.dartPeerPort | int | `9000` | DART P2P peer listen port (also the headless dart Service port) |
| runtimeAgent.enabled | bool | `true` | Whether the runtime-agent DaemonSet + dart headless Service are installed |
| runtimeAgent.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| runtimeAgent.image.repository | string | `"fast-sandbox/firecracker-runtime-agent"` | Runtime-agent image repository (built by manifests/release/build-fast-sandbox.sh) |
| runtimeAgent.image.tag | string | `"dev"` | Image tag |
| runtimeAgent.nodeSelector | object | `{"fast-sandbox.io/firecracker-node":"true"}` | Node selector selecting the Firecracker-capable nodes |
| runtimeAgent.registrySecret | string | `"fast-sandbox-agent-registry"` | Secret carrying the compiled agent registry configuration (registry.json key with artifact-store pull credentials); must be provisioned by the operator. |
| runtimeAgent.socketDir | string | `"/run/fast-sandbox/firecracker"` | Node hostPath sharing the agent UDS socket with fastlet Pods |
| runtimeAgent.stateRoot | string | `"/var/lib/fast-sandbox/firecracker"` | Node hostPath holding per-node Firecracker state (rootfs, snapshots). Each node needs its own directory; do not share across nodes. |
| runtimeEnvironments | string | `"version: v1alpha2\nenvironments:\n  default:\n    containerd:\n      socket: /run/containerd/containerd.sock\n      namespace: k8s.io\n      defaultSnapshotter: overlayfs\n      root: /var/lib/containerd\n    kubelet:\n      root: /var/lib/kubelet\n    runtimes:\n      container: {}\n      gvisor: {}\n      kata-qemu: {}\n      kata-clh: {}\n      kata-fc:\n        snapshotter: blockfile\n        configPath: /opt/kata/share/defaults/kata-containers/configuration-fc-fast-sandbox.toml\n      kata-dragonball:\n        configPath: /opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball-fast-sandbox.toml\n      boxlite: {}\n      firecracker:\n        firecracker:\n          binaryPath: /opt/fast-sandbox/firecracker/firecracker\n          jailerPath: /opt/fast-sandbox/firecracker/jailer\n          kernelPath: /opt/fast-sandbox/firecracker/vmlinux.bin\n          rootfsPath: /var/lib/fast-sandbox/firecracker/rootfs\n          stateRoot: /var/lib/fast-sandbox/firecracker"` |  |
| systemNamespace | string | `"fast-sandbox-system"` | Namespace for the fast-sandbox control plane workloads. Must match base.fastSandbox.namespaces.system (where the ServiceAccounts live). |

## Route signing keys

The controller signs the `f1.*` gateway routes with the Ed25519 private key from the `fast-sandbox-route-keys` Secret; the sandbox proxy verifies with the public key. By default the chart creates this Secret with the published development-only test keys (labeled `fast-sandbox.io/development-only: "true"`). For production, either provision the Secret yourself and set `routeKeys.existingSecret`, or set `routeKeys.privateKey` / `routeKeys.publicKey` with `routeKeys.developmentOnly=false`.

## Uninstalling the Chart

```bash
helm delete fast-sandbox
```

The CRDs and component RBAC are owned by the base release and are not affected (CRDs carry the `helm.sh/resource-policy: keep` annotation, so they must be deleted manually afterwards).

## License

Apache 2.0 License
