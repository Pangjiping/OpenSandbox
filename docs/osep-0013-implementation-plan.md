# OSEP-0013: Isolated Execution API — 提案分析与施工计划

## 一、提案概述

**PR**: [#989](https://github.com/opensandbox-group/OpenSandbox/pull/989)  
**作者**: @pjp  
**状态**: draft  
**文件**: `oseps/0013-isolated-execution-api.md` (727 行)

### 核心思路

将 [bubblewrap](https://github.com/containers/bubblewrap) 引入 execd，在运行中的 sandbox Pod 内部提供 per-execution 的 namespace 隔离。新增 `/v1/isolated/*` API 前缀，提供独立的 PID/mount/tmpfs/env namespace、workspace overlay（含 artifact recovery）和完整文件系统代理。

### 解决什么问题

1. **安全**: 当前 execd 在容器主 namespace 中 fork 子进程，多个执行共享 `/tmp`、PID namespace、网络、环境变量。先前的执行可以污染文件系统、ptrace 兄弟进程、从 `/proc/<pid>/environ` 读取敏感 token。
2. **吞吐**: RL 训练和评估场景中，step 之间切换需要完整 Pod 创建周期（runc 启动 40–100ms+），bwrap 可将 per-execution 冷启动压缩到 <1ms。

### 关键约束

- 只新增 `/v1/isolated/*` 端点，现有 API 零改动
- 不使用 user namespace（避免 CRI 嵌套要求），改用 real setuid
- bwrap 以静态二进制方式嵌入 execd（~800KB），不依赖 base image 预装
- SDK 不静默 fallback 到非隔离 API，由调用者决策

---

## 二、API 设计

### 端点总览

```
POST   /v1/isolated/session             创建隔离 bash 会话
GET    /v1/isolated/session/<id>        查询会话状态
POST   /v1/isolated/session/<id>/run    在会话中执行（SSE streaming）
DELETE /v1/isolated/session/<id>        销毁会话
GET    /v1/isolated/session/<id>/diff   下载 upper directory 为 tar.gz
POST   /v1/isolated/session/<id>/commit 将 upper 合并回 workspace

       /v1/isolated/session/<id>/files/*        文件系统代理（与 /files/* 同 schema）
       /v1/isolated/session/<id>/directories    目录操作

GET    /v1/isolated/capabilities        探测运行时能力
```

### 会话生命周期

```
execd (root)
 └── bwrap --unshare-pid --unshare-mount ... -- setpriv --reuid=N --regid=N bash
      └── bash (长驻进程，运行在 namespace 内，uid=N)
           └── run: sh -c <code> (每次 run fork)
```

- 创建会话 → 启动 bwrap+bash 长驻进程
- 多次 run 在同一 namespace 内执行
- 删除会话 → SIGKILL bwrap 进程组 → namespace 自动回收

### 隔离模式

| 特性 | strict | balanced |
|------|--------|----------|
| workspace.mode | overlay | rw |
| /tmp | tmpfs（私有） | bind container /tmp |
| share_net | true | true |
| env_passthrough | deny + blacklist | allow（透传） |
| seccomp | blocklist | blocklist |
| uid | real setuid | 同左 |

### Workspace 模式

| 模式 | 实现 | 写穿透 | 可回滚 | 场景 |
|------|------|--------|--------|------|
| `rw` | `--bind <ws> <ws>` | 是 | 否 | 持久化产物 |
| `overlay` | `--overlay-src <ws> --overlay <upper> <work> <ws>` | 仅 upper | 是 | 防止污染 |
| `ro` | `--ro-bind <ws> <ws>` | 否 | 否 | 只读分析 |

### 产物恢复（overlay + persist.enabled）

| 操作 | 含义 | 实现 |
|------|------|------|
| A: `GET .../diff` | 导出 upper 为 tar.gz | streaming tar 输出 |
| B: `POST .../commit` | 将 upper 合并回 workspace | mount overlayfs + rsync |

---

## 三、现有代码库分析

### execd 结构 (`components/execd/`)

```
components/execd/
  main.go                       # 入口：InitFlags → InitCodeRunner → NewRouter
  go.mod / go.sum / vendor/
  Makefile                      # CGO_ENABLED=0, multi-arch build
  Dockerfile                    # 多阶段：golang builder → alpine runtime
  bootstrap.sh                  # 启动脚本

  pkg/
    flag/
      flags.go                  # 全局 flag 变量
      parser.go                 # InitFlags() — 环境变量 + CLI flag
    log/                        # 结构化日志
    telemetry/
      init.go                   # OpenTelemetry 初始化
      record.go                 # HTTP metrics, execution metrics
    runtime/
      types.go                  # bashSession, ExecuteCodeRequest, ExecuteResultHook
      ctrl.go                   # Controller — sync.Map 管理各类 session
      bash_session.go           # createBashSession, runBashSession
      command.go                # runCommand, runBackgroundCommand
      env.go                    # mergeEnvs, loadExtraEnvFromFile
      workingdir.go             # ValidateWorkingDir
      language.go               # Language 类型定义
    web/
      router.go                 # Gin 路由注册（withFilesystem/withCode/withPTY 适配器模式）
      proxy.go                  # /proxy/* 反向代理
      controller/
        basic.go                # basicController: RespondError/RespondSuccess/bindJSON
        sse.go                  # SSE streaming（lazy header via sync.Once）
        codeinterpreting.go     # CodeInterpretingController + codeExecutionRunner 接口
        filesystem.go           # FilesystemController
        filesystem_upload.go    # 多部分上传
        filesystem_download.go  # 下载（含 Range 支持）
        pty_controller.go       # PTY 会话
        pty_ws.go               # WebSocket PTY
        metric.go               # 指标端点
        utils.go                # DeleteFile, ChmodFile, RenameFile, MakeDir 等
      model/
        session.go              # CreateSessionRequest/Response
        codeinterpreting.go     # RunCodeRequest, ServerStreamEvent
        filesystem.go           # FileInfo, FileMetadata, Permission
        pty.go                  # CreatePTYSessionRequest
        error.go                # ErrorResponse, ErrorCode
    util/
      pathutil/path.go          # 路径展开（无前缀 jail）
      glob/                     # Glob 匹配
    clone3compat/               # Seccomp clone3 兼容层
```

### 关键模式

1. **路由注册**: `group.METHOD("path", withXxx(func(c *Controller) { c.Handler() }))` 适配器模式
2. **控制器组合**: 嵌入 `*basicController` 获得 `RespondError`/`RespondSuccess`/`bindJSON`
3. **SSE streaming**: `setServerEventsHandler()` 将 `ExecuteResultHook` 回调适配为 SSE 事件；`sync.Once` 延迟设置响应头
4. **会话存储**: `sync.Map` 以 session UUID 为 key
5. **进程生命周期**: `exec.CommandContext` + `Setpgid: true`，销毁通过 `syscall.Kill(-pid, SIGKILL)`
6. **UID/GID**: 已有 `buildCredential(uid, gid)` 用于 setuid
7. **Telemetry**: `beginFilesystemMetric()` / `MarkSuccess()` / `Finish()` 模式

### 现有文件系统路径安全

当前**无前缀 jail**。路径通过 `pathutil.ExpandPath()` 展开（仅处理 `~` 和环境变量），没有 workspace 边界检查。安全模型依赖容器边界，而非代码级路径验证。OSEP-0013 需要在此之上增加 `filepath.Clean` + prefix 验证。

### 无已有 bubblewrap 代码

整个仓库中**不存在** bubblewrap、unshare、namespace、chroot、pivot_root、seccomp、landlock 相关代码。现有的 `clone3compat` 包仅处理外部 seccomp profile 与 clone3 的兼容性。

### SDK 结构

| 语言 | 路径 | 关键文件 |
|------|------|----------|
| Go | `sdks/sandbox/go/` | `types.go`（结构体）、`execd.go`（HTTP 客户端）、`sandbox_exec.go`（wrapper） |
| Python | `sdks/sandbox/python/src/opensandbox/` | `models/`（Pydantic）、`adapters/`（API wrapper） |
| TypeScript | `sdks/sandbox/javascript/src/` | `models/execd.ts`（接口）、`services/`（API 调用） |

### K8s / Server 关键点

- `server/opensandbox_server/services/k8s/provider_common.py` — `_build_execd_init_container()` 和 `_build_main_container()`
- `server/opensandbox_server/services/k8s/batchsandbox_provider.py` — `_build_pod_spec()`，已有 `opensandbox-bin` emptyDir
- execd **不作为独立服务部署**，而是通过 init container 注入到 sandbox Pod
- 当前无 `emptyDir` 后端支持（仅 Host、PVC、OSSFS）

---

## 四、施工计划

### Phase 1: 核心基础设施

#### 1-A. 新建 `pkg/isolation/` 包

| 文件 | 内容 |
|------|------|
| `pkg/isolation/isolator.go` | `Isolator` 接口 + `WrapOptions` 结构体 |
| `pkg/isolation/bwrap.go` | bwrap argv builder（固定分段顺序），`Wrap()` 实现 |
| `pkg/isolation/bwrap_test.go` | 表驱动测试：argv 顺序、互斥检查、env 模式 |
| `pkg/isolation/probe.go` | 启动探测：binary check → smoke test → seccomp → commit capability |
| `pkg/isolation/probe_test.go` | 探测结果解析测试 |
| `pkg/isolation/upper.go` | Upper 目录分配、GC、大小限制 |
| `pkg/isolation/upper_test.go` | 分配/释放/GC 逻辑测试 |
| `pkg/isolation/seccomp.go` | 加载 `/etc/execd/seccomp.bpf`，暴露为 `*os.File` |
| `pkg/isolation/bwrap` | 预编译的 musl 静态 bwrap 二进制（linux/amd64 + linux/arm64） |
| `pkg/isolation/bwrap_linux.go` | `//go:embed bwrap`，Linux 平台实现 |
| `pkg/isolation/bwrap_stub.go` | `//go:build !linux`，stub（Available = false） |

**Isolator 接口:**
```go
type Isolator interface {
    Name() string
    Available() bool
    Capabilities() Capabilities
    Wrap(cmd *exec.Cmd, opts WrapOptions) error
}
```

**WrapOptions** 按 OSEP §6 定义:
```go
type WrapOptions struct {
    Profile        Profile
    Workspace      WorkspaceSpec
    ExtraWritable  []string
    ShareNet       bool
    EnvPassthrough EnvSpec
    Uid, Gid       *uint32
    UpperDir       string
    WorkDir        string
}
```

**bwrap argv 固定分段顺序** (OSEP §7):
```
1. Namespace flags (--unshare-pid --unshare-uts --unshare-ipc, no --unshare-user)
2. --ro-bind / /
3. --tmpfs /tmp (strict) 或 --bind /tmp /tmp (balanced)
4. --tmpfs /run
5. --dev /dev
6. --proc /proc
7. Workspace segment (--bind / --overlay-src+--overlay / --ro-bind)
8. extra_writable segment
9. Env segment (--clearenv + --setenv)
10. --seccomp <fd>
11. -- setpriv --reuid=<n> --regid=<n> --init-groups <user cmd>
```

#### 1-B. Flag 扩展

修改 `pkg/flag/flags.go` 和 `pkg/flag/parser.go`：

| Flag | 默认值 | 环境变量 |
|------|--------|----------|
| `--isolation-upper-root` | `/var/lib/execd/isolation` | `EXECD_ISOLATION_UPPER_ROOT` |
| `--isolation-upper-max-bytes` | 8589934592 (8 GiB) | `EXECD_ISOLATION_UPPER_MAX_BYTES` |
| `--isolation-diff-max-bytes` | 4294967296 (4 GiB) | `EXECD_ISOLATION_DIFF_MAX_BYTES` |
| `--isolation-allowed-writable` | "" (拒绝所有) | `EXECD_ISOLATION_ALLOWED_WRITABLE` |

#### 1-C. main.go 集成

```go
// 在 flag.InitFlags() 之后
isolation.Init()
probeResult := isolation.Probe()
log.Info("isolation: available=%v isolator=%s version=%s commit_supported=%v",
    probeResult.Available, probeResult.Isolator, probeResult.Version, probeResult.CommitSupported)
```

---

### Phase 2: 会话生命周期

#### 2-A. 新建会话类型

`pkg/runtime/isolated_session.go`:
```go
type isolatedSession struct {
    id                  string
    mu                  sync.RWMutex    // per-session 锁
    opts                *CreateIsolatedSessionRequest
    cmd                 *exec.Cmd       // bwrap + bash 进程
    upperDir, workDir   string
    lastRunAt           time.Time
    createdAt           time.Time
    state               SessionState
    persistor           *UpperPersistor
}
```

`pkg/runtime/isolated_session_ctrl.go`:
- `CreateIsolatedSession(opts) -> (sessionID, error)` — validate, allocate upper, start bwrap+bash
- `GetIsolatedSession(id) -> (*SessionState, error)` — lookup, return state
- `RunInIsolatedSession(ctx, id, req) -> error` — acquire read lock, write code to bash stdin via pipe, stream output via SSE hooks, update lastRunAt
- `DeleteIsolatedSession(id) -> error` — acquire write lock, SIGKILL process group, upper → GC queue, remove from map
- `DiffUpper(id, w)` / `CommitUpper(id)` — artifact recovery

`pkg/runtime/ctrl.go` 修改:
```go
type Controller struct {
    // ... 现有字段 ...
    isolatedSessionMap sync.Map // map[sessionID]*isolatedSession
}
```

#### 2-B. 新建控制器

`pkg/web/controller/isolated_session.go`:
```go
type IsolatedSessionController struct {
    *basicController
    runner      isolatedSessionRunner  // 新接口，解耦测试
    chunkWriter sync.Mutex             // SSE 输出序列化
}

// 方法:
func (c *IsolatedSessionController) Create()         // POST /session
func (c *IsolatedSessionController) Get()            // GET /session/<id>
func (c *IsolatedSessionController) Run()            // POST /session/<id>/run
func (c *IsolatedSessionController) Delete()         // DELETE /session/<id>
func (c *IsolatedSessionController) Diff()           // GET /session/<id>/diff
func (c *IsolatedSessionController) Commit()         // POST /session/<id>/commit
func (c *IsolatedSessionController) Capabilities()   // GET /capabilities
```

`pkg/web/controller/isolated_session_files.go`:
```go
// 文件系统代理方法 — 与现有 FilesystemController 相同的 schema
func (c *IsolatedSessionController) GetFilesInfo()
func (c *IsolatedSessionController) SearchFiles()
func (c *IsolatedSessionController) DownloadFile()
func (c *IsolatedSessionController) UploadFile()
func (c *IsolatedSessionController) RemoveFiles()
func (c *IsolatedSessionController) RenameFiles()
func (c *IsolatedSessionController) ChmodFiles()
func (c *IsolatedSessionController) ReplaceContent()
func (c *IsolatedSessionController) MakeDirs()
func (c *IsolatedSessionController) RemoveDirs()
```

#### 2-C. Model 类型

`pkg/web/model/isolated_session.go` — 按 OSEP §2, §4 定义:

```go
type CreateIsolatedSessionRequest struct {
    Isolation IsolationSpec `json:"isolation"`
}
type IsolationSpec struct {
    Profile        string              `json:"profile"`         // "strict" | "balanced"
    Workspace      WorkspaceSpec       `json:"workspace"`
    ExtraWritable  []string            `json:"extra_writable,omitempty"`
    ShareNet       *bool               `json:"share_net,omitempty"`
    EnvPassthrough EnvPassthroughSpec  `json:"env_passthrough,omitempty"`
    Uid            *uint32             `json:"uid,omitempty"`
    Gid            *uint32             `json:"gid,omitempty"`
    IdleTimeoutSeconds int             `json:"idle_timeout_seconds,omitempty"`
}
type WorkspaceSpec struct {
    Path    string       `json:"path"`
    Mode    string       `json:"mode"`    // "rw" | "overlay" | "ro"
    Persist *PersistSpec `json:"persist,omitempty"`
}
// ... RunInSessionRequest, CreateSessionResponse, CapabilitiesResponse ...
```

#### 2-D. 路由注册

修改 `pkg/web/router.go`:

```go
isolated := r.Group("/v1/isolated")
{
    isolated.POST("/session", withIsolated(func(c *IsolatedSessionController) { c.Create() }))
    isolated.GET("/session/:sessionId", withIsolated(func(c *IsolatedSessionController) { c.Get() }))
    isolated.POST("/session/:sessionId/run", withIsolated(func(c *IsolatedSessionController) { c.Run() }))
    isolated.DELETE("/session/:sessionId", withIsolated(func(c *IsolatedSessionController) { c.Delete() }))
    isolated.GET("/session/:sessionId/diff", withIsolated(func(c *IsolatedSessionController) { c.Diff() }))
    isolated.POST("/session/:sessionId/commit", withIsolated(func(c *IsolatedSessionController) { c.Commit() }))
    isolated.GET("/session/:sessionId/files/info", withIsolated(func(c *IsolatedSessionController) { c.GetFilesInfo() }))
    isolated.GET("/session/:sessionId/files/download", withIsolated(func(c *IsolatedSessionController) { c.DownloadFile() }))
    isolated.POST("/session/:sessionId/files/upload", withIsolated(func(c *IsolatedSessionController) { c.UploadFile() }))
    isolated.DELETE("/session/:sessionId/files", withIsolated(func(c *IsolatedSessionController) { c.RemoveFiles() }))
    isolated.POST("/session/:sessionId/files/mv", withIsolated(func(c *IsolatedSessionController) { c.RenameFiles() }))
    isolated.POST("/session/:sessionId/files/permissions", withIsolated(func(c *IsolatedSessionController) { c.ChmodFiles() }))
    isolated.POST("/session/:sessionId/files/replace", withIsolated(func(c *IsolatedSessionController) { c.ReplaceContent() }))
    isolated.GET("/session/:sessionId/files/search", withIsolated(func(c *IsolatedSessionController) { c.SearchFiles() }))
    isolated.POST("/session/:sessionId/directories", withIsolated(func(c *IsolatedSessionController) { c.MakeDirs() }))
    isolated.DELETE("/session/:sessionId/directories", withIsolated(func(c *IsolatedSessionController) { c.RemoveDirs() }))
    isolated.GET("/capabilities", withIsolated(func(c *IsolatedSessionController) { c.Capabilities() }))
}
```

新增适配器:
```go
func withIsolated(fn func(*controller.IsolatedSessionController)) gin.HandlerFunc {
    return func(ctx *gin.Context) {
        fn(controller.NewIsolatedSessionController(ctx))
    }
}
```

---

### Phase 3: Workspace Overlay 与文件系统代理

#### 3-A. MergedView — overlay 感知的文件系统视图

`pkg/isolation/merged_view.go`:

```go
type MergedView struct {
    LowerDir string
    UpperDir string
    Uid, Gid uint32
    Mode     WorkspaceMode  // RW / Overlay / RO
}
```

路径解析策略（OSEP §11）：

| 操作 | 策略 |
|------|------|
| Read (info/download) | 先查 upper；whiteout → 404；miss → fall through lower |
| Search | 遍历 upper + lower，merge 去重，跳过 whiteout 路径 |
| Write (upload/replace) | 写入 upper 路径；`os.Chown(path, uid, gid)` |
| Delete | 在 upper 中创建 whiteout（char device 0,0）；目录：opaque xattr |
| Move | 源：创建 whiteout；目标：写入 upper |
| Permissions (chmod/chown) | upper 有文件 → 直接操作；仅 lower 有 → 先 copy-up |
| mkdir | 在 upper 创建；lower 已存在目录 → 创建 opaque marker |
| **ro mode** | 所有写操作返回 `403 Forbidden` |

Whiteout 处理：
```go
const (
    opaqueXattr    = "trusted.overlay.opaque"
    whiteoutPrefix = ".wh."
)

func isWhiteout(name string) bool { return strings.HasPrefix(name, whiteoutPrefix) }
```

#### 3-B. Diff 导出

`pkg/isolation/diff.go`:
- `GET /session/<id>/diff`
- Streaming `application/gzip`，`Transfer-Encoding: chunked`
- 使用 `archive/tar` + `compress/gzip`
- 强制 `--isolation-diff-max-bytes` 限制，超限返回 413

#### 3-C. Commit 合并

`pkg/isolation/commit.go`:
- `POST /session/<id>/commit`
- 流程：`mkdir merged` → `mount -t overlay` → `rsync -aHAX --delete` → `umount` → `rmdir merged`
- 处理 whiteout（char 0,0 → 删除 workspace 对应路径）
- 处理 opaque（`trusted.overlay.opaque=y` → 删除子树再复制 upper）
- v1 仅支持 `strategy = overwrite`
- gVisor 下 commit 标记为 `commit_supported = false`，返回 503

#### 3-D. 并发控制

Per-session `sync.RWMutex`（OSEP §12）：

| 操作 | 锁类型 |
|------|--------|
| run | Read |
| diff | Read |
| Filesystem read | Read |
| Filesystem write | Read |
| commit | **Write** |
| Delete session | **Write** |
| Reset upper | **Write** |

---

### Phase 4: 空闲 GC

`pkg/runtime/isolated_session.go`:
- `lastRunAt` 时间戳，每次 run 完成时更新
- 后台 goroutine 每 60s 扫描
- `now - lastRunAt > idle_timeout_seconds` → 自动 DELETE
- `idle_timeout_seconds = 0` 禁用
- Session GET 返回 `created_at`、`last_run_at`、`idle_remaining_seconds`

---

### Phase 5: Spec, SDK, K8s 集成

#### 5-A. OpenAPI Spec

修改 `specs/execd-api.yaml`:
- 新增 schema: `CreateIsolatedSessionRequest`、`IsolationSpec`、`WorkspaceSpec`、`PersistSpec`、`RunInSessionRequest`、`CapabilitiesResponse`
- 新增路径: `/v1/isolated/*`（文件和目录端点复用已有 filesystem schema）
- 版本号保持不变（additive change）

#### 5-B. SDK 更新（纯增量）

| SDK | 文件 | 变更 |
|-----|------|------|
| **Go** | `sdks/sandbox/go/types.go` | 新增 `CreateIsolatedSessionRequest`、`IsolationSpec`、`IsolatedSession`、`IsolationCapabilities` |
| | `sdks/sandbox/go/execd.go` | 新增 `CreateIsolatedSession()`、`RunInIsolatedSession()`、`DeleteIsolatedSession()`、`IsolatedSessionDiff()`、`IsolatedSessionCommit()` |
| | `sdks/sandbox/go/sandbox_exec.go` | 新增 `IsolatedSessionFiles` 类型（与 `Sandbox.Files` 同 API） |
| **Python** | `src/opensandbox/models/isolated.py` | Pydantic 模型 |
| | `src/opensandbox/adapters/isolated_adapter.py` | Adapter 类 |
| **TS** | `src/models/isolated.ts` | Interface 定义 |
| | `src/services/isolated.ts` | Service 类 |

**关键原则**: SDK 不静默 fallback。`capabilities.available = false` 时由调用者决定。

#### 5-C. K8s / Server

| 文件 | 变更 |
|------|------|
| `server/.../k8s/provider_common.py` | 新增 `isolation-upper` emptyDir volume，挂载到 `--isolation-upper-root` 路径 |
| `server/.../k8s/batchsandbox_provider.py` | `_build_pod_spec()` volumes 列表添加 emptyDir |
| `server/.../k8s/agent_sandbox_provider.py` | 同上 |
| `components/execd/bootstrap.sh` | 若 `EXECD_ISOLATION_UPPER_ROOT` 设置则创建目录 |

**安全上下文**: execd 需以 root 运行（或 `CAP_SYS_ADMIN`）以创建 mount/PID namespace。当前 execd 已在专用 sandbox 容器内运行，满足此要求。

---

### Phase 6: 构建与 CI

| 文件 | 变更 |
|------|------|
| `components/execd/Makefile` | 新增 `build-bwrap` target: 用 musl-gcc 静态编译 bwrap for linux/{amd64,arm64} |
| `components/execd/Dockerfile` | 无需修改（bwrap 由 `//go:embed` 嵌入 execd 二进制） |
| `components/execd/scripts/build-bwrap.sh` | 从源码交叉编译 bwrap 的脚本 |
| `.github/workflows/execd-test.yml` | Linux runner 安装 bwrap 运行集成测试；非 Linux skip |

---

### Phase 7: 测试计划

#### 单元测试（无需 bwrap，无需 root）

| 包 | 测试内容 |
|----|----------|
| `pkg/isolation/bwrap_test.go` | Argv builder：所有 profile×mode 组合的分段顺序；env passthrough deny/allow 模式；`extra_writable` allowlist 验证；`/tmp` 互斥检查 |
| `pkg/isolation/probe_test.go` | 版本字符串解析；capabilities 序列化 |
| `pkg/isolation/upper_test.go` | 分配/释放生命周期；GC 过期；大小限制 |
| `pkg/isolation/merged_view_test.go` | Whiteout 过滤；opaque 目录合并；search 去重；ro mode 拒绝写 |
| `pkg/isolation/commit_test.go` | Whiteout 处理；rsync 正确性 |
| `pkg/web/controller/isolated_session_test.go` | 使用 fakeRunner 的 CRUD 测试；SSE 流式传输；错误响应 |
| `pkg/web/model/isolated_session_test.go` | 请求验证（必填字段、字段类型） |

#### 集成测试（Linux，bwrap 可用，build tag `linux`）

- 端到端生命周期：create → run → run → diff → commit → delete
- Overlay CoW：会话内写入不修改原始 workspace；commit 合并正确
- PID 隔离：会话内 `echo $$` → 1
- `/tmp` 隔离：不同会话的 `/tmp` 互相不可见
- 文件系统代理：upload → download 往返；delete → whiteout；search 合并 upper+lower
- `persist.enabled = false`：会话关闭后 upper 销毁；diff 返回 404
- `commit_supported = false`（模拟 gVisor）：commit 返回 503；diff 正常
- 多会话：两个并发会话有独立 namespace
- 空闲 GC：超时自动销毁；run 重置计时器

#### 冒烟测试

扩展 `components/execd/tests/smoke_api.py` 覆盖隔离会话生命周期。

#### 手动验证

- 测量 bwrap namespace 启动开销 <1ms
- 验证 upper 大小限制触发 SIGKILL
- 验证 commit 正确处理 overlayfs whiteout 和 opaque 语义

---

## 五、文件变更汇总

### 新建文件 (~25 个)

```
components/execd/pkg/isolation/
  isolator.go              # Isolator 接口 + WrapOptions
  bwrap.go                 # bwrap argv builder + Wrap()
  bwrap_test.go            # argv 构建测试
  bwrap_linux.go           //go:embed bwrap, Linux 实现
  bwrap_stub.go            //go:build !linux stub
  bwrap                    # 预编译 musl 静态二进制
  probe.go                 # 启动探测
  probe_test.go            # 探测测试
  upper.go                 # Upper 目录管理 + GC
  upper_test.go            # Upper 测试
  seccomp.go               # Seccomp BPF 加载
  merged_view.go           # Overlay 文件系统视图
  merged_view_test.go      # MergedView 测试
  commit.go                # Commit 实现
  commit_test.go           # Commit 测试
  diff.go                  # Diff (tar.gz 导出)
  diff_test.go             # Diff 测试

components/execd/pkg/runtime/
  isolated_session.go      # isolatedSession 结构体
  isolated_session_ctrl.go # 会话 CRUD 方法

components/execd/pkg/web/controller/
  isolated_session.go       # IsolatedSessionController
  isolated_session_files.go # 文件系统代理处理器

components/execd/pkg/web/model/
  isolated_session.go       # 请求/响应类型

components/execd/scripts/
  build-bwrap.sh            # bwrap 交叉编译脚本
```

### 修改文件 (~15 个)

```
components/execd/
  pkg/flag/flags.go              # 新增 flag 变量
  pkg/flag/parser.go             # 注册 flag + env 默认值
  main.go                        # 嵌入提取 + 探测启动
  pkg/runtime/ctrl.go            # 新增 isolatedSessionMap
  pkg/web/router.go              # 注册 /v1/isolated/* 路由组
  pkg/web/controller/codeinterpreting.go  # 扩展接口（或新建独立接口）
  Makefile                       # build-bwrap target
  Dockerfile                     # 无改动（//go:embed 已包含二进制）

specs/
  execd-api.yaml                 # 新 schema + 路径

sdks/sandbox/go/
  types.go, execd.go, sandbox_exec.go  # 新类型 + 方法

sdks/sandbox/python/src/opensandbox/
  models/isolated.py, adapters/isolated_adapter.py

sdks/sandbox/javascript/src/
  models/isolated.ts, services/isolated.ts

server/opensandbox_server/services/k8s/
  provider_common.py             # 新增 isolation-upper emptyDir
  batchsandbox_provider.py       # volumes 列表
  agent_sandbox_provider.py      # volumes 列表

components/execd/
  bootstrap.sh                   # 创建 upper root 目录

.github/workflows/
  execd-test.yml                 # 集成测试步骤
```

---

## 六、关键设计决策与风险

### 设计决策

| 决策 | 选择 | 原因 |
|------|------|------|
| UID 隔离 | Real setuid，非 user namespace | 避免 CRI 嵌套要求；不同会话不同 host UID，文件权限在内核级执行 |
| 文件系统代理 | 在 namespace 外直接访问 upper/lower（host view） | 比通过 bwrap 代理简单，无往返开销 |
| bwrap 分发 | `//go:embed` 静态嵌入 | 版本与 execd 绑定，CVE 修复随 execd 发布 |
| 会话模型 | 长驻 bwrap+bash，多次 run | 复用 namespace，避免每次 run 都创建/销毁 |
| Commit 实现 | overlayfs mount + rsync | 利用内核 overlayfs 正确处理 whiteout/opaque |
| 控制器 | 新建独立 `IsolatedSessionController` | 保持隔离逻辑自包含，不改动现有控制器 |
| 会话存储 | 新建 `isolatedSessionMap sync.Map` | 类型安全，不混入现有 session map |

### 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| bwrap 共享内核 | 不防内核漏洞 | 明确定位为性能加速+进程隔离，非安全边界替代。不可信代码仍需 gVisor/Firecracker |
| Overlay mount 需 CAP_SYS_ADMIN | 受限环境不可用 | 启动探测，capabilities 端点反映真实状态；diff 不受影响 |
| bwrap 历史 CVE（如 CVE-2024-42472） | 符号链接竞态 | 静态嵌入固定版本，跟踪上游发布 |
| Upper 磁盘耗尽 | execd 崩溃 | 硬限制 + 后台 du 检查 + GC；超限 SIGKILL |
| Commit 并发 run | Workspace 损坏 | per-session Write 锁阻止并发 |
| gVisor 不支持 overlay mount | Commit 不可用 | capabilities 标记 `commit_supported = false`；diff 和隔离执行仍正常 |
| 非 Linux 平台 | 不支持 | `Available() = false`，`/v1/isolated/*` 返回 503 |

---

## 七、工作量估算

| Phase | 内容 | 估算 |
|-------|------|------|
| 1 | 核心基础设施（isolation 包、flag、嵌入） | 3-4 天 |
| 2 | 会话生命周期（controller、router、model） | 2-3 天 |
| 3 | Overlay + 文件系统代理（MergedView、diff、commit） | 3-4 天 |
| 4 | 空闲 GC | 0.5-1 天 |
| 5 | Spec + SDK + K8s 集成 | 2-3 天 |
| 6 | 构建 + CI | 1 天 |
| 7 | 测试（单元 + 集成 + 冒烟） | 2-3 天 |
| **总计** | | **~14-19 天** |

---

## 八、PR #1008 Review — Filesystem 待修问题

### 安全问题

#### S1. [P1] Upper root 隐藏不完整 — 跨 session 数据泄露
- **文件**: `components/execd/pkg/isolation/bwrap.go:79-83`
- **问题**: `filepath.Dir(opts.UpperDir)` 对 `/var/lib/execd/isolation/<id>/upper` 求值为 `/var/lib/execd/isolation/<id>`，只隐藏当前 session 的目录。父目录 `/var/lib/execd/isolation/` 通过 `--ro-bind / /` 仍然可见，session 内进程可读其他 session 的 upper 目录。
- **修复**: 隐藏 `filepath.Dir(filepath.Dir(opts.UpperDir))` 即整个 upper root。

#### S2. [P2] MergedView 读路径跟随符号链接
- **文件**: `components/execd/pkg/isolation/merged_view.go:93-173`
- **问题**: `Stat()`、`Open()`、`ReadFile()` 使用 `os.Stat`/`os.Open`/`os.ReadFile`，跟随 symlink。session 内进程创建 `upper/x -> /etc/shadow`，MergedView 以 execd 权限读取宿主文件。`rejectSymlink()` 已存在但仅用于写路径。
- **修复**: 在读路径的 upper 查询中加入 `rejectSymlink()` 检查。

#### S3. [P2] Chmod 直接修改 lower（原始 workspace）文件
- **文件**: `components/execd/pkg/isolation/merged_view.go:343-361`
- **问题**: 文件仅存在于 lower 时，`Chmod()` 直接 `os.Chmod(lowerPath)`，修改原始 workspace，破坏隔离。
- **修复**: 先 copy-up 到 upper 再 chmod。

### 功能问题（SDK 兼容性）

#### F1. [P2] Search 返回 `[]string`，SDK 期望 `FileInfo[]`
- **文件**: `components/execd/pkg/web/controller/isolated_session_files.go:84-89`
- **问题**: 普通 `/files/search` 返回 `FileInfo` 对象，isolated 版返回纯路径字符串。SDK adapter 解析 FileInfo 时会失败。
- **修复**: `SearchFiles()` 返回 `FileInfo` 对象，与普通文件 API contract 一致。

#### F2. [P2] Search 忽略 `path` query 参数
- **文件**: `components/execd/pkg/web/controller/isolated_session_files.go:73-90`
- **问题**: handler 忽略 `path` query，始终搜索整个 workspace。SDK 调用者期望 scope 到指定路径。
- **修复**: 将 `path` query 传递给 `MergedView.Search()` 作为搜索根目录。

#### F3. [P2] Rename 从 query 读参数，SDK POST JSON body
- **文件**: `components/execd/pkg/web/controller/isolated_session_files.go:187-205`
- **问题**: SDK adapter POST JSON body（`[{old_path, new_path}]`），与普通 `/files/mv` contract 一致。handler 从 query param 读取，忽略 body。
- **修复**: 从 JSON body 读取 rename 请求。

#### F4. [P2] Replace 从 query 读参数，SDK POST JSON body
- **文件**: `components/execd/pkg/web/controller/isolated_session_files.go:229-252`
- **问题**: 同 F3。SDK adapter POST JSON body，handler 从 query 读取。
- **修复**: 从 JSON body 读取 replace 请求。

#### F5. [P2] Mkdir 从 query 读参数，SDK POST JSON body
- **文件**: `components/execd/pkg/web/controller/isolated_session_files.go:254-268`
- **问题**: 同 F3。SDK adapter POST JSON body，handler 从 query 读取。
- **修复**: 从 JSON body 读取 mkdir 请求。

#### F6. [P2] Delete contract 用 query params，spec 定义 JSON body
- **文件**: `components/execd/pkg/web/controller/isolated_session_files.go:171-185`
- **问题**: handler 用 `QueryArray("path")`，但 OpenAPI spec（`execd-api.yaml:1372`）定义 JSON request body。生成的 SDK client 会 POST body。
- **修复**: 同时接受 query params 和 JSON body，或改为 body only 与 spec 一致。

### 低优先级

#### L1. [P2] Rename 不创建 whiteout
- **文件**: `components/execd/pkg/isolation/merged_view.go:301-341`
- **问题**: rename lower-only 文件（copy-up + rename in upper）后，lower 源文件通过 MergedView 仍可见，未创建 `.wh.` 文件。
- **修复**: rename 后在 upper 中创建 `.wh.<name>` 遮蔽 lower 源。

#### L2. [P2] Remove 不创建 whiteout
- **文件**: `components/execd/pkg/isolation/merged_view.go:241-266`
- **问题**: lower-only 文件返回错误 "cannot remove from read-only workspace lower"。应创建 whiteout 正确遮蔽。
- **修复**: 创建 `.wh.<name>` whiteout 而非返回错误。

#### L3. [P2] RemoveAll 只删 upper，lower 仍可见
- **文件**: `components/execd/pkg/isolation/merged_view.go:268-283`
- **问题**: `RemoveAll` 只 `os.RemoveAll(upper)`。lower 条目通过 ReadDir/Stat 仍可见。
- **修复**: 对 lower-only 文件创建 whiteout。
