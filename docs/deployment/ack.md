---
title: ACK 部署
description: 在阿里云容器服务 Kubernetes 版（ACK）上部署 OpenSandbox —— 创建集群、新增节点、渲染部署各组件及 ACK 环境注意事项。
---

# ACK 部署

OpenSandbox 可部署在任何标准 Kubernetes 集群上，ACK 完全兼容标准 Kubernetes API。组件安装细节见 [Kubernetes 部署](/deployment/)，本文描述在 ACK 上的部署步骤与环境注意事项。

## 前提条件

- 阿里云账号，已开通容器服务 ACK 并完成默认角色授权
- Kubernetes 1.21.1+
- Helm 3.x（仅用作模板渲染器）、`kubectl`
- 集群 KubeConfig 凭证（见[第二步](#第二步-连接集群)）

## 第一步：创建 ACK 集群

推荐 **ACK 托管集群（Pro）**，按[创建 ACK 托管集群](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/create-an-ack-managed-cluster-2/)创建，关键配置：

| 配置项 | 建议 |
|--------|------|
| 集群版本 | ≥ 1.21 |
| 网络插件 | Terway（沙箱 Pod 拥有 VPC 内可直接路由的 Pod IP） |
| 初始节点池 | 2–3 台通用型实例，承载控制面组件 |
| 安全组 | 放行 Worker 节点间 VPC 内互通 |

## 第二步：连接集群

按[获取集群 KubeConfig 并通过 kubectl 工具连接集群](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/obtain-the-kubeconfig-file-of-a-cluster-and-use-kubectl-to-connect-to-the-cluster/)配置 `~/.kube/config`，然后验证：

```bash
kubectl get nodes
```

## 第三步：新增节点

为沙箱工作负载创建**独立节点池**（可开启自动伸缩），与控制面组件隔离，见[创建和管理节点池](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/create-a-node-pool/)；存量 ECS 可通过[添加已有节点](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/add-existing-ecs-instances-to-an-ack-cluster/)导入。日常管理见[节点管理](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/node-management/)。

::: tip 污点隔离
沙箱节点池配置污点（Taint）时，需在 BatchSandbox Pod 模板中添加对应的 Toleration，否则沙箱 Pod 无法调度。
:::

::: warning fast-sandbox 节点池要求
fast-sandbox（Firecracker）的 Worker 节点必须是**裸金属服务器**（需要 KVM），且节点池内**所有节点 CPU 型号必须相同**（锁定单一实例规格，不混部不同代际，否则微虚拟机快照无法跨节点恢复）。建议单独建节点池。
:::

## 第四步：部署 OpenSandbox

部署方式：`helm template` 将 chart 渲染为 YAML，`kubectl diff` 审阅变更后 `kubectl apply --server-side` 应用到集群。渲染产物与 values 文件纳入 Git 管理。

按组件顺序部署（与 [Deployment Order](/deployment/#deployment-order) 一致）：

```text
base → controller → fast-sandbox* → ingress-gateway → server
```

\* `fast-sandbox` 为可选组件；启用时须在 ingress-gateway 与 server 之前部署。

注意：

- 不要与 `helm install` / `helm upgrade` 混用，双方会互相覆盖
- 使用 `--server-side`（Server-Side Apply）：CRD 体量超过 client-side apply 的注解上限

准备仓库与命名空间：

```bash
git clone https://github.com/opensandbox-group/OpenSandbox.git
cd OpenSandbox
git checkout release-1.1.0   # 部署对应发布版本
mkdir -p out                 # 渲染产物目录

# 渲染式部署不会自动创建 namespace，先建好
kubectl create namespace opensandbox-system --dry-run=client -o yaml \
  | kubectl apply --server-side -f -
kubectl create namespace opensandbox --dry-run=client -o yaml \
  | kubectl apply --server-side -f -
```

### 1. 部署 base（CRD + RBAC）

```bash
helm template base manifests/charts/base > out/base.yaml

kubectl diff -f out/base.yaml
kubectl apply --server-side -f out/base.yaml
```

apply 输出 21 行 `serverside-applied`（1 Namespace + 7 CRD + 11 ClusterRole + 2 ClusterRoleBinding）。验证 CRD：

```bash
kubectl get crd | grep -E 'sandbox\.(opensandbox|fast)\.io'
```

```text
batchsandboxes.sandbox.opensandbox.io               2026-09-28T08:48:54Z
pools.sandbox.opensandbox.io                        2026-09-28T08:48:55Z
sandboxes.sandbox.fast.io                           2026-09-28T08:49:04Z
sandboxpools.sandbox.fast.io                        2026-09-28T08:48:59Z
sandboxsnapshots.sandbox.fast.io                    2026-09-28T08:49:06Z
sandboxsnapshots.sandbox.opensandbox.io             2026-09-28T08:48:57Z
sandboxtemplates.sandbox.fast.io                    2026-09-28T08:49:07Z
```

### 2. 部署 controller

```bash
helm template opensandbox-controller manifests/charts/controller \
  -n opensandbox-system \
  --set controller.replicaCount=2 > out/controller.yaml

kubectl diff -f out/controller.yaml
kubectl apply --server-side -f out/controller.yaml

kubectl rollout status deployment/opensandbox-controller-manager \
  --namespace opensandbox-system --timeout=180s
```

apply 输出 6 行 `serverside-applied`（SA + Role/Binding + ClusterRole/Binding + Deployment）。rollout 与 Pod 状态：

```text
deployment "opensandbox-controller-manager" successfully rolled out

opensandbox-controller-manager-865887c57-mvbr9   1/1   Running   0   6m25s   10.79.205.208   ap-southeast-1.10.79.205.204
opensandbox-controller-manager-865887c57-rhgxn   1/1   Running   0   37s     10.79.205.209   ap-southeast-1.10.79.205.203
```

### 3. 部署 fast-sandbox

必须在 server 之前部署：server 启动时会连接 FastPath gRPC 端点。

#### 准备制品仓库（OSS）

fast-sandbox 的 golden image 与快照存放在 S3 兼容的制品仓库。ACK 上使用同 region 的 OSS 与 VPC 内网域名（避免公网流量）：

1. 在集群同 region 创建 OSS Bucket（如 `my-sandbox-images`）
2. 创建 RAM 子账号 AK/SK，授予该 Bucket 读写权限
3. VPC 内网 Endpoint 格式：`https://oss-<region>.internal.aliyuncs.com`（如 `https://oss-ap-southeast-1.internal.aliyuncs.com`）

#### 配置凭证 Secret

::: warning
registry.json 的最终 schema 由 fast-sandbox 上游编译工具生成，以下为**占位符**示例，仅用于使 Pod 启动；实际拉取制品前需按工具产物补全。
:::

```bash
cat > /tmp/registry.json <<'EOF'
{
  "endpoint": "https://oss-ap-southeast-1.internal.aliyuncs.com",
  "bucket": "my-sandbox-images",
  "accessKeyId": "<YOUR_ACCESS_KEY_ID>",
  "accessKeySecret": "<YOUR_ACCESS_KEY_SECRET>"
}
EOF

kubectl create secret generic fast-sandbox-agent-registry \
  -n opensandbox-system \
  --from-file=registry.json=/tmp/registry.json \
  --dry-run=client -o yaml | kubectl apply --server-side -f -
rm /tmp/registry.json   # AK/SK 不落盘、不进 Git
```

渲染并部署（`artifactStore` 与 Bucket / Endpoint 保持一致）：

```bash
helm template fast-sandbox manifests/charts/fast-sandbox \
  -n opensandbox-system \
  --set artifactStore.store=s3://my-sandbox-images/publish \
  --set artifactStore.endpoint=https://oss-ap-southeast-1.internal.aliyuncs.com \
  > out/fast-sandbox.yaml

kubectl diff -f out/fast-sandbox.yaml
kubectl apply --server-side -f out/fast-sandbox.yaml
```

apply 输出 13 行 `serverside-applied`（PDB + SA + Secret/ConfigMap + RBAC + 2 Service + DaemonSet + Deployment）。验证 Pod 状态与节点标签：

```text
fast-sandbox-controller-7d79b6447b-8q5bp   1/1   Running
firecracker-runtime-hkg9d                  2/2   Running
firecracker-runtime-z8mq9                  2/2   Running

NAME                           STATUS   KVM    FIRECRACKER-NODE
ap-southeast-1.10.79.205.203   Ready    true   true
ap-southeast-1.10.79.205.204   Ready    true   true
```

readiness 循环自动为节点打 4 个标签（`kvm`、`firecracker-node`、`cpu-identity`、`cpu-template`）。其中 `cpu-identity` 编码 CPU 型号（厂商-家族-型号），**节点池内该值必须一致**，微虚拟机快照才能跨节点恢复：

```bash
kubectl get nodes -L sandbox.fast.io/kvm,fast-sandbox.io/cpu-identity,fast-sandbox.io/firecracker-node
```

::: warning 节点需加载 kvm 内核模块
ECS 裸金属节点默认不加载 kvm 模块，readiness 会报 `/dev/kvm unusable: device does not exists`。在节点上执行 `modprobe kvm kvm_amd`（通过 privileged Pod `nsenter -t 1 -m` 或节点 SSH），然后 `kubectl rollout restart daemonset/firecracker-runtime -n opensandbox-system` 使 Pod 重建 `/dev`。模块加载不跨重启持久，节点重启后需重做（建议通过节点池 bootstrap 脚本或自定义镜像持久化）。
:::

模板构建、镜像准备等前置步骤见 [fast-sandbox runtime 部署指南](https://github.com/opensandbox-group/OpenSandbox/blob/main/manifests/HELM-DEPLOYMENT.md#fast-sandbox-runtime-firecracker)。

### 4. 部署 ingress-gateway

Kubernetes 环境中沙箱 Pod 仅有 ClusterIP，客户端流量须经 ingress-gateway 路由。在 server 之前部署，server 首次安装即可携带公告配置。

`providerType=fast-sandbox` 时网关强制要求 secure-access 签名密钥环（OSEP-0011：server 签发路由令牌，网关验证）。生成密钥并与 server 共用：

```bash
KEY=$(openssl rand -base64 32)   # 保存好，部署 server 时复用

helm template ingress-gateway manifests/charts/ingress-gateway \
  -n opensandbox-system \
  --set gateway.providerType=fast-sandbox \
  --set gateway.fastpathEndpoint=fast-sandbox-fastpath.opensandbox-system.svc:9090 \
  --set "gateway.secureAccess.keys[0].key_id=a" \
  --set "gateway.secureAccess.keys[0].key=$KEY" \
  > out/ingress-gateway.yaml

kubectl diff -f out/ingress-gateway.yaml
kubectl apply --server-side -f out/ingress-gateway.yaml

kubectl rollout status deployment/opensandbox-ingress-gateway \
  --namespace opensandbox-system --timeout=180s
```

验证：

```text
deployment "opensandbox-ingress-gateway" successfully rolled out

opensandbox-ingress-gateway-66bd4bf7b7-59nfz   1/1   Running   0   67s
opensandbox-ingress-gateway-66bd4bf7b7-dbc2v   1/1   Running   0   56s
```

### 5. 部署 lifecycle server

创建 API Key Secret（生产环境建议使用外部密钥管理系统）：

```bash
read -s OPENSANDBOX_API_KEY
kubectl create secret generic opensandbox-api-key \
  --namespace opensandbox-system \
  --from-literal=api-key="${OPENSANDBOX_API_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -
unset OPENSANDBOX_API_KEY
```

values 文件引用 Secret，并配置网关公告。`secureAccess` 须使用部署 ingress-gateway 时生成的同一把密钥，`activeKey` 对应 key_id；`gatewayRouteMode` 需与 ingress-gateway chart 的 `gateway.gatewayRouteMode` 一致（默认均为 `header`）：

```yaml
# values-server.yaml
server:
  env:
    - name: OPENSANDBOX_SERVER_API_KEY
      valueFrom:
        secretKeyRef:
          name: opensandbox-api-key
          key: api-key
  gateway:
    enabled: true
    host: opensandbox-ingress-gateway.opensandbox-system.svc
    secureAccess:
      activeKey: a
      keys:
        - key_id: a
          key: <部署网关时生成的 base64 密钥>
```

::: info
`configToml`（沙箱工作负载命名空间、镜像地址、运行时等）与 PostgreSQL 持久化等同样在此文件配置，渲染前补齐。完整参考见 [Kubernetes 部署](/deployment/)。
:::

渲染并部署：

```bash
helm template opensandbox-server manifests/charts/server \
  -n opensandbox-system \
  -f values-server.yaml > out/server.yaml

kubectl diff -f out/server.yaml
kubectl apply --server-side -f out/server.yaml

kubectl rollout status deployment/opensandbox-server \
  --namespace opensandbox-system --timeout=180s

kubectl port-forward --namespace opensandbox-system \
  service/opensandbox-server 8080:80
curl --fail http://127.0.0.1:8080/health
```

预期输出：

```text
deployment "opensandbox-server" successfully rolled out

{"status":"healthy"}
```

### 可选：部署共享 SandboxPool

SandboxPool（`sandbox.fast.io`）是 fast-sandbox 的容量与策略单元：预热 Fastlet 舰队规模（`capacity`）、不可变运行时 profile（`runtime`）、每个沙箱的资源形状（`sandboxResources`）与放置约束（`fastletTemplate`）。同一池内的所有沙箱共享这些设置。仓库提供了示例 `manifests/examples/sandboxpool-fast-sandbox.yaml`：

```yaml
apiVersion: sandbox.fast.io/v1alpha2
kind: SandboxPool
metadata:
  name: shared-pool
  namespace: opensandbox-dataplane
spec:
  runtime: firecracker
  sandboxResources:
    cpu: "1"
    memory: 2Gi
    pids: 256
  capacity:
    poolMin: 5
    poolMax: 10
    bufferMin: 0
    bufferMax: 2
  maxSandboxesPerPod: 4
  fastletTemplate:
    spec:
      containers:
      - name: fastlet
        image: opensandbox/fsb-fastlet:release-1.1.1-rc.1
        imagePullPolicy: IfNotPresent
        env:
        - name: FAST_SANDBOX_RUNTIME_AGENT_SOCKET
          value: /run/fast-sandbox/firecracker/runtime.sock
        volumeMounts:
        - name: agent-socket
          mountPath: /run/fast-sandbox/firecracker
      volumes:
      - name: agent-socket
        hostPath:
          path: /run/fast-sandbox/firecracker
          type: DirectoryOrCreate
      nodeSelector:
        fast-sandbox.io/firecracker-node: "true"
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: sandbox-fastlet
              topologyKey: kubernetes.io/hostname
  warmImages: []
```

注意：`fastletTemplate` 必须包含名为 `fastlet` 的容器（fast-sandbox companion 镜像）并挂载节点上 runtime-agent 的 UDS socket，否则 controller 会拒绝 reconcile。需要 egress 网络策略时，参考集成环境的完整示例 `scripts/fast-sandbox-env/manifests/pool/firecracker-egress-pool.yaml`（egress sidecar + `infraComponents`/`actionHandlers` 声明）。

部署并验证：

```bash
kubectl apply --server-side -f manifests/examples/sandboxpool-fast-sandbox.yaml

kubectl get pods -n opensandbox-dataplane
kubectl get sandboxpool shared-pool -n opensandbox-dataplane -o jsonpath='{.status.conditions[?(@.type=="RuntimeReady")].status}'
```

`poolMin=5` 预热 5 个 Fastlet（反亲和分散到各节点），全部就绪后 `RuntimeReady` 转为 `True`：

```text
NAME                        READY   STATUS    RESTARTS   AGE
shared-pool-fastlet-5nh85   2/2     Running   0          54s
shared-pool-fastlet-cxrln   2/2     Running   0          54s
shared-pool-fastlet-gzhml   2/2     Running   0          54s
shared-pool-fastlet-wnlsx   2/2     Running   0          54s
shared-pool-fastlet-zdrd4   2/2     Running   0          54s

True
```

### 升级

切换到新版本标签，重新渲染全部组件，diff 审阅后逐个 apply：

```bash
git fetch --tags
git checkout release-1.2.0

helm template base manifests/charts/base > out/base.yaml
helm template opensandbox-controller manifests/charts/controller \
  -n opensandbox-system > out/controller.yaml
helm template ingress-gateway manifests/charts/ingress-gateway \
  -n opensandbox-system \
  --set gateway.fastpathEndpoint=fast-sandbox-fastpath.opensandbox-system.svc:9090 \
  > out/ingress-gateway.yaml
helm template opensandbox-server manifests/charts/server \
  -n opensandbox-system -f values-server.yaml > out/server.yaml

kubectl diff -f out/base.yaml && kubectl apply --server-side -f out/base.yaml
kubectl diff -f out/controller.yaml && kubectl apply --server-side -f out/controller.yaml
kubectl diff -f out/server.yaml && kubectl apply --server-side -f out/server.yaml
```

`kubectl diff` 存在差异时退出码为 `1`，脚本化时不应视为失败。

### 对外暴露 Server

在 `values-server.yaml` 中设置 `server.service.type: LoadBalancer`（ACK 自动创建 SLB），重新渲染并 apply。生产环境建议使用内网 SLB，沙箱流量走 ingress gateway。

## ACK 环境注意事项

| 主题 | 说明 |
|------|------|
| 网络插件 | 推荐 Terway；Flannel 模式下 Pod IP 为 overlay 地址，暴露沙箱地址前需确认路由可达 |
| fast-sandbox | 必须裸金属节点（KVM）+ 相同 CPU 型号，否则跳过该组件，使用默认运行时。详见 [fast-sandbox runtime](https://github.com/opensandbox-group/OpenSandbox/blob/main/manifests/HELM-DEPLOYMENT.md#fast-sandbox-runtime-firecracker) |
| 镜像拉取 | 默认镜像托管在 Docker Hub，VPC 内建议通过 ACR 同步后覆盖 `server.image.repository` 及 `configToml` 中的沙箱镜像地址 |
| Server 持久化 | 生产环境建议使用 RDS for PostgreSQL（见 [PostgreSQL 持久化](/deployment/#use-postgresql-for-server-persistence)） |
| 监控 | Controller 的 Prometheus 指标见 [Operator Metrics](/deployment/#operator-metrics)，可接入 ARMS Prometheus |

## 卸载

按部署逆序删除渲染产物。注意：删除 `out/base.yaml` 会连同 CRD 一起删除（kubectl 不理会 `resource-policy: keep`），并级联删除所有自定义资源：

```bash
kubectl delete -f out/server.yaml
kubectl delete -f out/ingress-gateway.yaml
kubectl delete -f out/fast-sandbox.yaml      # 如部署
kubectl delete -f out/controller.yaml
kubectl delete -f out/base.yaml
```

如需保留 CRD 仅删除组件，跳过 `out/base.yaml` 即可；CRD 清理见 [Kubernetes 部署 → Uninstall](/deployment/#uninstall)。

## 相关链接

- [Kubernetes 部署](/deployment/) — 组件完整安装与配置
- [Kubernetes Controller 概述](/architecture/control-plane/operator) — CRD 与控制器机制
- [ACK 快速入门](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/getting-started/)
- [创建 ACK 托管集群](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/create-an-ack-managed-cluster-2/)
- [创建和管理节点池](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/create-a-node-pool/)
- [添加已有节点](https://help.aliyun.com/zh/ack/ack-managed-and-ack-dedicated/user-guide/add-existing-ecs-instances-to-an-ack-cluster/)
