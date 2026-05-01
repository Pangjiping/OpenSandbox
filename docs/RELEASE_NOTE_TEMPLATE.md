# [component name] [version]

Use this template for single-component releases (SDK / server / Docker image / K8s component).

## What's New

Some docs if needed.

### ✨ Features
- Feature-1 (#123)
- Feature-2 (#456)

### 🐛 Bug Fixes
- Bug-fix (#456)

### ⚠️ Breaking Changes
- xxx (#789)

### 📦 Misc
- workflow update (#789)
- deps update (#789)
- tests update (#789)

## 👥 Contributors

Thanks to these contributors ❤️

- @alice
- @bob

---

# Packages [version]

Use this template for the repo-wide aggregate release (triggered by `packages/vX.Y.Z` tag). This release bundles all component Docker images and the Helm chart.

## Component Images

| Component | Image | Tag |
|---|---|---|
| execd | `sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox/execd` | `vX.Y.Z` |
| code-interpreter | `sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox/code-interpreter` | `vX.Y.Z` |
| ingress | `sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox/ingress` | `vX.Y.Z` |
| egress | `sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox/egress` | `vX.Y.Z` |
| controller | `sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox/controller` | `vX.Y.Z` |
| task-executor | `sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox/task-executor` | `vX.Y.Z` |
| server | `sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com/opensandbox/server` | `vX.Y.Z` |

## What's New

### execd
- feat: xxx (#123)
- fix: xxx (#456)

### code-interpreter
- feat: xxx (#123)

### ingress
- fix: xxx (#456)

### egress
- fix: xxx (#456)

### controller
- feat: xxx (#123)

### task-executor
- feat: xxx (#123)

### server
- feat: xxx (#123)
- fix: xxx (#456)

### Helm Chart
- chore: bump images to vX.Y.Z

### Docs / CI / Misc
- workflow update (#789)

## 👥 Contributors

Thanks to these contributors ❤️

- @alice
- @bob

## Helm Chart

All-in-one chart bundling controller and server dependencies.

```bash
# List available versions
helm show chart oci://ghcr.io/alibaba/helm-charts/opensandbox

# Install (replace X.Y.Z with the target version)
helm install opensandbox \
  oci://ghcr.io/alibaba/helm-charts/opensandbox \
  --version X.Y.Z \
  --namespace opensandbox-system \
  --create-namespace

# Upgrade
helm upgrade opensandbox \
  oci://ghcr.io/alibaba/helm-charts/opensandbox \
  --version X.Y.Z \
  --namespace opensandbox-system
```
