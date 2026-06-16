# OSEP-0013: Execution Plan

基于 [`docs/osep-0013-implementation-plan.md`](./osep-0013-implementation-plan.md) 的施工计划，补充 gap 分析、执行顺序调整、各阶段验收标准。

## 进展

### Phase 1 ✅ 已完成

| 文件 | 状态 |
|------|------|
| `pkg/isolation/` 包 (10 文件) | ✅ isolator/bwrap/probe/upper/seccomp/MergedView + 测试 |
| `pkg/flag/` — 单一 `--isolation-config` flag | ✅ (替代原 4 个 flag) |
| `main.go` 集成 (probe + runner 初始化) | ✅ |
| `Dockerfile` 多阶段构建 (musl-static bwrap v0.11.2) | ✅ |
| `Makefile` test-integration target | ✅ |
| `smoke_bwrap.sh` CI smoke test | ✅ |
| `.golangci.yml` 关 perfsprint | ✅ |

### Phase 2 ✅ 已完成 (Model + Router + Controller + Runtime)

| 文件 | 状态 |
|------|------|
| `pkg/web/model/isolated_session.go` | ✅ Request/Response types (已扁平化) |
| `pkg/web/model/error.go` | ✅ SERVICE_UNAVAILABLE, SESSION_NOT_FOUND |
| `pkg/web/router.go` | ✅ /v1/isolated/* 路由组 (17 端点) |
| `pkg/web/controller/isolated_session.go` | ✅ CRUD + SSE + Capabilities handler |
| `pkg/web/controller/isolated_session_files.go` | ✅ 文件系统代理 (10 handler, 用 vfs.FS 接口) |
| `pkg/runtime/isolated_session.go` | ✅ Session 结构体 + start/stop |
| `pkg/runtime/isolated_session_ctrl.go` | ✅ IsolatedRunner (Create/Get/Run/Delete, envs 注入) |
| `pkg/runtime/isolated_session_stub.go` | ✅ Windows 桩 |
| `pkg/runtime/ctrl.go` | ✅ isolatedSessionMap |
| `pkg/web/controller/sse.go` | ✅ writeSingleEvent 提到 basicController |
| `pkg/isolation/merged_view.go` | ✅ Overlay 文件系统视图 (实现 vfs.FS) |
| SSE streaming | ✅ StdoutCallback + context 取消 |
| `cmd.Wait()` zombie 修复 | ✅ |

### Phase 2 测试 ✅

| 文件 | 状态 |
|------|------|
| `pkg/runtime/isolated_session_test.go` | ✅ 15 单元测试 (stub isolator) |
| `pkg/isolation/merged_view_test.go` | ✅ 20 单元测试 |
| `pkg/runtime/bwrap_test/` (9 文件) | ✅ 70 集成测试 (linux+bwrap) |
| `pkg/runtime/bwrap_test/bwrap_workflow_test.go` | ✅ 6 E2E workflow 测试 (Run↔File API 交叉) |
| CI job `bwrap-smoke` | ✅ meson 构建 bwrap v0.11.2 + sudo 测试 |

### Phase 3 ✅ 已完成 (Seccomp + Telemetry + Spec + 测试补全)

| 文件 | 状态 |
|------|------|
| `pkg/isolation/seccomp_gen.go` | ✅ BPF 生成器 (elastic/go-seccomp-bpf, 纯 Go), 支持 Config override |
| `pkg/isolation/seccomp_gen_test.go` | ✅ BPF 结构测试 |
| `pkg/isolation/bwrap_linux.go` | ✅ memfd + ExtraFiles fd 传递 |
| `pkg/telemetry/isolation.go` | ✅ IsolationStatsProvider + RecordIsolatedRun |
| `pkg/telemetry/isolation_test.go` | ✅ Provider / Record 测试 |
| `pkg/telemetry/init.go` | ✅ 3 新指标注册 |
| `pkg/runtime/isolated_session_ctrl.go` | ✅ statsSnapshot + telemetry provider |
| `pkg/web/controller/isolated_session.go` | ✅ Run handler telemetry 计时 |
| `pkg/runtime/bwrap_test/bwrap_seccomp_test.go` | ✅ 5 seccomp 集成 + 2 config override E2E |
| `pkg/runtime/bwrap_test/bwrap_extra_writable_test.go` | ✅ 3 ExtraWritable 集成测试 |
| `pkg/runtime/bwrap_test/bwrap_coverage_gaps_test.go` | ✅ 11 gap-coverage 测试 |
| `specs/execd-api.yaml` | ✅ 17 endpoints, 已更新 (扁平化 request, 无 IsolationSpec) |

### PR Review 改进 (已 squash 至 `5ff9482f`)

| 改进 | 说明 |
|------|------|
| TOML 配置文件 | `--isolation-config` 单一 flag 替代 4 个 CLI flag; `pkg/isolation/config.go` + 8 单元测试 |
| Seccomp 可覆盖 | `[seccomp].deny` 完全替换内置 denylist (nil = 用内置, 非 nil = 替换, 不合并) |
| API 扁平化 | 移除 `IsolationSpec` 包装层, 删除 `PersistSpec`/`ArtifactURLs`/`Cwd` 死代码 |
| Envs 注入 | `RunInIsolatedSession` 接受 `envs map[string]string`, shell escape 防注入 |
| VFS 接口抽取 | `pkg/vfs/vfs.go` — `FS` 接口, `MergedView` 实现, file handler 用接口 |
| 配置示例 | `configs/isolation.example.toml` 含完整默认值和 seccomp 参考 |
| session 生命周期 | 资源清理、overlay upper/work 透传、end marker 行中拼接 |
| E2E 测试 | 6 个 Run↔File API workflow 测试, 2 个 seccomp config override E2E |

### 已知问题

#### test job 预存失败

- `bash_session_test.go:485` 预存 bug，非本 PR。

#### bwrap overlay `--` 解析

- bwrap v0.11.2 overlay 模式 `--overlay-src SRC --overlay MNT -- bash` 中 `--` 偶发被 overlay 消费，`--noprofile` 被当作 bwrap 选项报错。改用 `--tmp-overlay` 规避。

#### overlayfs API→Run 方向限制 (内核行为，非 bug)

- overlay 模式下，MergedView 写入 upper 目录（宿主机）后，bwrap 内部 overlayfs 挂载的 VFS 缓存不会刷新 → Run 看不到 API 写的文件。只有 Run→API 方向可用。需双向文件交换用 `rw` 模式。已在 `MergedView` 类型文档和 `WriteFile` 方法中注明。

### 已解决问题

#### stdin pipe 文件重定向

- 早期 `echo data > /path/file` 在 stdin pipe 中不产生 marker。根因为 zombie 进程泄漏 (`cmd.Wait()` 缺失) 导致的资源耗尽。修复后所有文件重定向测试正常通过，含 3 个 ExtraWritable 测试。

#### end marker 行中拼接

- `cat` 无换行文件后，`echo __ISOLATED_RUN_END__ $?` 拼在同一行 → `HasPrefix` 漏掉 → scanner 永久阻塞。改用 `strings.Index` 定位 marker，提取前缀为输出。

#### overlay 模式 upper 目录未生效

- `start()` 没把 `s.upperDir`/`s.workDir` 传给 `WrapOptions` → bwrap 用 `--tmp-overlay`（内部 tmpfs）→ Run 写入和 MergedView 互相不可见。加两行赋值修复。

### Phase 4 ✅ 已完成 (SDK + Server + E2E)

| 项 | 状态 |
|------|------|
| Python SDK | ✅ IsolationService + IsolationSession handle + adapter (async/sync) |
| Go SDK | ✅ IsolationCreate/Session handle + ExecdClient methods |
| JS/TS SDK | ✅ IsolationService + adapter + session handle |
| Kotlin SDK | ✅ IsolationService/Session + OkHttp adapter |
| C# SDK | ✅ IIsolatedSessions + adapter + session handle |
| Server bwrap 分发 | ✅ Docker + K8s init container 拷贝 bwrap |
| bootstrap.execd.isolation extension | ✅ CAP_SYS_ADMIN + apparmor/seccomp=unconfined |
| Probe diagnostics | ✅ capabilities API 返回 message 字段 |
| E2E tests (5 语言) | ✅ Python/Go/JS/Java/C# 全部通过 |

### 未完成 / 遗留

| 项 | 状态 | 说明 |
|------|------|------|
| Isolated file handler 兼容性 | ⬜ 阻塞 `session.files` SDK API | isolated file handler 的请求/响应格式与普通 FilesystemController 不一致，SDK 的 FilesystemAdapter 通过 generated client 发请求，格式不兼容导致 400/parse error。需要对齐 isolated file handler 使其完全兼容普通 handler 的 multipart/JSON 格式 |
| `session.files` E2E 测试 | ⬜ 被上述问题阻塞 | 当前文件操作 e2e 通过 `session.run("echo ... > file")` 验证，未走 SDK filesystem API |
| Diff / Commit 真实实现 | ⬜ 二期 | 503 stub，需 overlayfs mount + rsync |
| FilesystemController VFS 迁移 | ⬜ 二期 | TODO 已留, 未来统一 `/files` 和 `/v1/isolated/.../files` |
| bwrap 版本解析 | ⬜ 小问题 | probe 报 `version=None`，`bwrap --version` 输出到 stderr 但解析正则可能不匹配 |

## 前置条件

- [ ] 确认 bwrap 版本: bubblewrap v0.10.0+ (含 CVE-2024-42472 修复)
- [ ] 确认目标 base image 的 libcap 版本满足 `setpriv` 需求
- [ ] 确认 Kind e2e 环境 `/dev/fuse` 可用（或确认用不上 fuse）

---

## Phase 1: 核心基础设施 (3-4d)

### 1.1 `pkg/isolation/` 包 — 接口定义

**新建 `pkg/isolation/isolator.go`**

```go
type Isolator interface {
    Name() string
    Available() bool
    Capabilities() Capabilities
    Wrap(cmd *exec.Cmd, opts WrapOptions) error
}

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

验收: `go build ./pkg/isolation/...` 通过；接口在未实现时编译通过。

### 1.2 bwrap argv builder + 静态嵌入

**新建文件:**

| 文件 | 职责 |
|------|------|
| `pkg/isolation/bwrap.go` | argv 构建（固定分段顺序），`Wrap()` 实现 |
| `pkg/isolation/bwrap_test.go` | 表驱动: 所有 profile×mode 组合的分段顺序；env deny/allow；extra_writable allowlist；`/tmp` 互斥 |
| `pkg/isolation/bwrap_linux.go` | `//go:build linux`，`Wrap()` + memfd seccomp |
| `pkg/isolation/bwrap_stub.go` | `//go:build !linux`，`Available() = false` |
| Dockerfile | 多阶段构建 (musl-gcc + meson v0.11.2)，static bwrap 与 execd 一起分发 |

**bwrap argv 固定分段顺序** (来自 OSEP §7):

```
1. Namespace flags (--unshare-pid --unshare-uts --unshare-ipc, 无 --unshare-user)
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

验收:
- `go test ./pkg/isolation/ -run TestBwrap` 全部通过
- 每个 profile (strict/balanced) × workspace mode (rw/overlay/ro) 组合有对应 case

### 1.3 启动探测

**新建 `pkg/isolation/probe.go`**

- Binary check: `bwrap --version` 解析版本号
- Smoke test: `bwrap --ro-bind / / -- true`
- Seccomp check: `bwrap --seccomp <fd> ... -- true`
- (二期) Commit check: `mount -t overlay` 可用性

探测结果缓存为全局 `ProbeResult`。一期 `commit_supported`、`diff_supported` 固定为 `false`。

验收:
- 有 bwrap: `Available=true, Isolator="bubblewrap"`
- 无 bwrap: `Available=false`，`/v1/isolated/*` 全部返回 503
- `go test ./pkg/isolation/ -run TestProbe` 覆盖版本字符串解析

### 1.4 Upper 目录管理

**新建 `pkg/isolation/upper.go`**

- 分配: `AllocateUpper(root string, maxBytes int64) (upperDir, workDir string, err error)`
- GC: 后台 goroutine 每 60s 检查 `lastRunAt`，超时回收
- 大小限制: 硬限制 `--isolation-upper-max-bytes`，超限发送 SIGKILL

验收: `go test ./pkg/isolation/ -run TestUpper`

### 1.5 Seccomp BPF 生成

**新建 `pkg/isolation/seccomp_gen.go`**

- 使用 `elastic/go-seccomp-bpf` (已 vendored, 纯 Go) 生成 BPF 字节码
- Default-allow denylist: mount, ptrace, init_module 等 40+ 危险 syscall
- 架构感知：`arch.GetInfo("")` 自动过滤不存在的 syscall
- 运行时通过 memfd 写入 BPF，fd 号传给 `bwrap --seccomp <fd>` via `cmd.ExtraFiles`
- `NewBwrap()` 启动时生成并缓存；非 Linux 平台 `seccompBPF` 为空，`Wrap()` 不传 seccomp

### 1.6 Flag 扩展

**修改 `pkg/flag/flags.go`** — 新增变量:

```go
var (
    IsolationUpperRoot     string
    IsolationUpperMaxBytes int64
    IsolationDiffMaxBytes  int64
    IsolationAllowedWritable []string
)
```

**修改 `pkg/flag/parser.go`** — 注册 flag + env:

| Flag | Env | Default |
|------|-----|---------|
| `--isolation-upper-root` | `EXECD_ISOLATION_UPPER_ROOT` | `/var/lib/execd/isolation` |
| `--isolation-upper-max-bytes` | `EXECD_ISOLATION_UPPER_MAX_BYTES` | `8589934592` (8 GiB) |
| `--isolation-diff-max-bytes` | `EXECD_ISOLATION_DIFF_MAX_BYTES` | `4294967296` (4 GiB) |
| `--isolation-allowed-writable` | `EXECD_ISOLATION_ALLOWED_WRITABLE` | `""` (none) |

### 1.7 main.go 集成

```go
// 在 flag.InitFlags() 之后, controller.InitCodeRunner() 之前
isolationProbe := isolation.Probe(isolation.ProbeConfig{
    UpperRoot:     flag.IsolationUpperRoot,
    UpperMaxBytes: flag.IsolationUpperMaxBytes,
})
log.Info("isolation: available=%v isolator=%s version=%s commit_supported=%v",
    isolationProbe.Available, isolationProbe.Isolator,
    isolationProbe.Version, isolationProbe.CommitSupported)
controller.SetIsolationProbe(isolationProbe)
```

验收:
- 启动日志含 isolation probe 结果
- `make build` 通过
- 非 Linux CI skip bwrap 相关测试

### 1.8 Makefile 扩展

新增 target:

```makefile
.PHONY: build-bwrap
build-bwrap: ## Cross-compile static bwrap with musl
    bash scripts/build-bwrap.sh

.PHONY: test-integration
test-integration: ## Run integration tests (Linux + bwrap required)
    go test -v -tags=linux -run Integration ./pkg/isolation/...
```

**新建 `scripts/build-bwrap.sh`** — musl-gcc 静态编译 linux/{amd64,arm64}，输出到 `pkg/isolation/bwrap`。

---

## Phase 2: Model + Router + Spec 契约先行 (2d)

> **决策**: 先定义 API 契约（model + OpenAPI spec），再实现 controller。避免契约与实现不一致。

### 2.1 Model 类型

**新建 `pkg/web/model/isolated_session.go`** — 严格按 OSEP §2, §4:

```go
type CreateIsolatedSessionRequest struct {
    Isolation IsolationSpec `json:"isolation"`
}

type IsolationSpec struct {
    Profile           string              `json:"profile"`           // "strict" | "balanced"
    Workspace         WorkspaceSpec       `json:"workspace"`
    ExtraWritable     []string            `json:"extra_writable,omitempty"`
    ShareNet          *bool               `json:"share_net,omitempty"`
    EnvPassthrough    EnvPassthroughSpec  `json:"env_passthrough,omitempty"`
    Uid               *uint32             `json:"uid,omitempty"`
    Gid               *uint32             `json:"gid,omitempty"`
    IdleTimeoutSeconds int                `json:"idle_timeout_seconds,omitempty"`
}

type WorkspaceSpec struct {
    Path    string       `json:"path"`
    Mode    string       `json:"mode"`    // "rw" | "overlay" | "ro"
    Persist *PersistSpec `json:"persist,omitempty"`
}

type PersistSpec struct {
    Enabled bool `json:"enabled"`
}

type EnvPassthroughSpec struct {
    Mode      string   `json:"mode"`      // "allow" | "deny"
    Allowlist []string `json:"allowlist,omitempty"`
    Denylist  []string `json:"denylist,omitempty"`
}

type CreateSessionResponse struct {
    SessionID string       `json:"session_id"`
    State     SessionState `json:"state"`
}

type SessionState struct {
    Status               string    `json:"status"`  // "active" | "destroyed"
    CreatedAt            time.Time `json:"created_at"`
    LastRunAt            time.Time `json:"last_run_at"`
    IdleRemainingSeconds *int      `json:"idle_remaining_seconds,omitempty"`
}

type RunInSessionRequest struct {
    Code    string   `json:"code"`
    Timeout *float64 `json:"timeout,omitempty"`
    Env     []string `json:"env,omitempty"`
}

type CapabilitiesResponse struct {
    Available       bool   `json:"available"`
    Isolator        string `json:"isolator,omitempty"`
    Version         string `json:"version,omitempty"`
    CommitSupported bool   `json:"commit_supported"` // 一期固定 false
    DiffSupported   bool   `json:"diff_supported"`   // 一期固定 false
}
```

### 2.2 OpenAPI Spec

**修改 `specs/execd-api.yaml`**:
- 新增 schema: 上述所有类型
- 新增路径: `/v1/isolated/*` (共 17 个端点)
- 文件/directory 端点复用已有 filesystem schema
- 版本号不变 (additive change)

### 2.3 路由注册 (骨架)

**修改 `pkg/web/router.go`** — 新增路由组:

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

验收:
- `go build` 编译通过 (controller 方法可为空实现)
- OpenAPI spec 与路由定义无差异

### 2.4 SDK Types (纯增量，无实现)

**Go SDK** (`sdks/sandbox/go/`):

| 文件 | 变更 |
|------|------|
| `types.go` | 新增 `CreateIsolatedSessionRequest`, `IsolationSpec`, `WorkspaceSpec`, `PersistSpec`, `CreateSessionResponse`, `SessionState`, `CapabilitiesResponse` |
| `execd.go` | 新增 `CreateIsolatedSession()`, `RunInIsolatedSession()`, `DeleteIsolatedSession()`, `IsolatedSessionDiff()` (stub → error), `IsolatedSessionCommit()` (stub → error), `IsolatedSessionFiles()`, `IsolatedSessionCapabilities()` |
| `sandbox_exec.go` | 新增 `IsolatedSessionFiles` 类型（与 `Sandbox.Files` 同 API） |

**Python SDK** (`sdks/sandbox/python/src/opensandbox/`):

| 文件 | 变更 |
|------|------|
| `models/isolated.py` | Pydantic models |
| `adapters/isolated_adapter.py` | `IsolatedSessionAdapter` — 方法签名 |

**TypeScript SDK** (`sdks/sandbox/javascript/src/`):

| 文件 | 变更 |
|------|------|
| `models/isolated.ts` | Interface definitions |
| `services/isolated.ts` | `IsolatedSessionService` — 方法签名 |

**关键原则**: SDK 不静默 fallback。`capabilities.available = false` 时由调用者决策。

---

## Phase 3: 会话生命周期 (2-3d)

### 3.1 新建会话类型

**新建 `pkg/runtime/isolated_session.go`**:

```go
type isolatedSession struct {
    id        string
    mu        sync.RWMutex
    opts      *model.CreateIsolatedSessionRequest
    cmd       *exec.Cmd       // bwrap + bash
    stdin     io.WriteCloser  // bash stdin pipe
    upperDir  string
    workDir   string
    lastRunAt time.Time
    createdAt time.Time
    state     model.SessionState
}
```

### 3.2 新建会话管理器

**新建 `pkg/runtime/isolated_session_ctrl.go`**:

```go
type IsolatedSessionRunner interface {
    CreateIsolatedSession(opts *model.CreateIsolatedSessionRequest) (*model.CreateSessionResponse, error)
    GetIsolatedSession(id string) (*model.SessionState, error)
    RunInIsolatedSession(ctx context.Context, id string, req *model.RunInSessionRequest) error
    DeleteIsolatedSession(id string) error
    DiffUpper(id string, w io.Writer) error
    CommitUpper(id string) error
}
```

方法实现:
- `Create`: validate → allocate upper → build bwrap argv → `exec.CommandContext(bgCtx, bwrapPath, args...)` → start bash → store in map
- `Get`: lookup → return state + idle remaining
- `Run`: acquire Read lock → write code to bash stdin pipe → stream output via SSE hooks → update `lastRunAt`
- `Delete`: acquire Write lock → SIGKILL (-pid) → upper → GC queue → remove from map
- `Diff`/`Commit`: 见 Phase 4

### 3.3 Controller 实现

**修改 `pkg/runtime/ctrl.go`** — 新增:

```go
type Controller struct {
    // ... existing ...
    isolatedSessionMap sync.Map // map[sessionID]*isolatedSession
    isolationProbe     *isolation.ProbeResult
}
```

**新建 `pkg/web/controller/isolated_session.go`**:

```go
type IsolatedSessionController struct {
    *basicController
    runner      runtime.IsolatedSessionRunner
    chunkWriter sync.Mutex
}

func NewIsolatedSessionController(ctx *gin.Context) *IsolatedSessionController {
    return &IsolatedSessionController{
        basicController: newBasicController(ctx),
        runner:          codeRunner, // 或独立初始化
    }
}

// 方法:
func (c *IsolatedSessionController) Create()
func (c *IsolatedSessionController) Get()
func (c *IsolatedSessionController) Run()
func (c *IsolatedSessionController) Delete()
// Diff/Commit: 一期空实现，返回 503 + "not implemented yet"
func (c *IsolatedSessionController) Diff()    // → 503
func (c *IsolatedSessionController) Commit()  // → 503
func (c *IsolatedSessionController) Capabilities()
```

**SSE streaming 适配**: `Run()` 复用现有 `setServerEventsHandler()` 模式，`ExecuteResultHook` 回调适配为 SSE 事件。注意：隔离 run 的输出来自 bash stdin pipe (stdout/stderr reader)，而非 Jupyter kernel IOPub。

验收:
- `go build` 通过
- 端到端手动测试: create → run (echo $$ → 1) → delete
- `GET /v1/isolated/capabilities` 返回正确 probe 结果

---

## Phase 4: Overlay + 文件系统代理 (2-3d)

> **一期范围**: MergedView (简单版) + 文件系统代理控制器。Diff/Commit 留空实现。

### 4.1 MergedView — 先简单版本

**新建 `pkg/isolation/merged_view.go`**:

```go
type MergedView struct {
    LowerDir string
    UpperDir string
    Uid, Gid uint32
    Mode     WorkspaceMode
}

// 核心方法:
func (m *MergedView) Stat(path string) (os.FileInfo, error)
func (m *MergedView) ReadDir(path string) ([]os.DirEntry, error)
func (m *MergedView) Open(path string) (*os.File, error)
func (m *MergedView) WriteFile(path string, data []byte, perm os.FileMode) error
func (m *MergedView) Remove(path string) error
func (m *MergedView) MkdirAll(path string, perm os.FileMode) error
func (m *MergedView) Chmod(path string, mode os.FileMode) error
```

**路径安全**: `filepath.Clean` + prefix 验证是**强制检查项**，不是可选。

```go
func (m *MergedView) safePath(path string) (string, error) {
    cleaned := filepath.Clean(path)
    // 拒绝绝对路径越界
    if strings.HasPrefix(cleaned, "..") {
        return "", errs.PathTraversal
    }
    return cleaned, nil
}
```

**读写策略** (一期简单实现):

| 操作 | 策略 |
|------|------|
| Read (Stat/Open/ReadDir) | 先查 upper；miss → lower |
| Write (WriteFile/MkdirAll) | 写入 upper；`os.Chown` to uid/gid |
| Delete (Remove/RemoveAll) | 仅 upper 有 → 直接删除；lower 有 → v1 skip，记录 warning |
| ro mode | 所有写返回 403 |

**whiteout/opaque 语义** 二期实现。一期 MergedView 不创建 whiteout，不做 opaque marker。

### 4.2 文件系统代理 Controller

**新建 `pkg/web/controller/isolated_session_files.go`**:

与现有 `FilesystemController` 相同 schema，每个方法:
1. 从 `:sessionId` 获取 session → 创建 `MergedView`
2. 调用对应 `MergedView` 方法
3. 序列化响应

验收:
- Upload → Download 往返一致
- RO mode: write 返回 403
- Search 在 write → read 后可见

### 4.3 Diff 导出 — 一期空实现

**新建 `pkg/isolation/diff.go`**:

```go
func DiffUpper(upperDir string, w io.Writer, maxBytes int64) error {
    return fmt.Errorf("diff not implemented yet")
}
```

Controller: `GET /session/<id>/diff` → `RespondError(503, "not_implemented", "diff available in phase 2")`

### 4.4 Commit 合并 — 一期空实现

**新建 `pkg/isolation/commit.go`**:

```go
func CommitUpper(upperDir, workspace string) error {
    return fmt.Errorf("commit not implemented yet")
}
```

Controller: `POST /session/<id>/commit` → `RespondError(503, "not_implemented", "commit available in phase 2")`

`CapabilitiesResponse.commit_supported` 固定返回 `false`。

### 4.5 并发控制

Per-session `sync.RWMutex` (commit/delete 锁预留，一期仅 run + FS 操作用 Read 锁):

| 操作 | 锁 |
|------|-----|
| run | Read |
| FS read | Read |
| FS write | Read |
| delete session | **Write** |
| (二期) diff | Read |
| (二期) commit | **Write** |

---

## Phase 5: 空闲 GC (0.5-1d)

**修改 `pkg/runtime/isolated_session.go`**:

```go
func (c *Controller) startIsolationGC() {
    go func() {
        ticker := time.NewTicker(60 * time.Second)
        for range ticker.C {
            c.isolatedSessionMap.Range(func(key, value any) bool {
                s := value.(*isolatedSession)
                s.mu.RLock()
                idle := time.Since(s.lastRunAt)
                timeout := time.Duration(s.opts.Isolation.IdleTimeoutSeconds) * time.Second
                s.mu.RUnlock()
                if timeout > 0 && idle > timeout {
                    c.DeleteIsolatedSession(s.id)
                }
                return true
            })
        }
    }()
}
```

- `idle_timeout_seconds = 0` 禁用 GC
- Session GET 返回 `idle_remaining_seconds`

验收:
- 设置 5s 超时 → 6s 后 session 自动删除
- `idle_timeout_seconds = 0` → 永不过期
- run 重置计时器

---

## Phase 6: Server / K8s 集成 (1-2d)

### 6.1 Volume 配置

**修改 `server/opensandbox_server/services/k8s/provider_common.py`**:

```python
# 在 _build_execd_init_container() 或等效位置
ISOLATION_UPPER_VOLUME = "isolation-upper"
ISOLATION_UPPER_MOUNT = "/var/lib/execd/isolation"

def _add_isolation_volume(self, volumes, volume_mounts):
    volumes.append({
        "name": ISOLATION_UPPER_VOLUME,
        "emptyDir": {"sizeLimit": "8Gi"}
    })
    volume_mounts.append({
        "name": ISOLATION_UPPER_VOLUME,
        "mountPath": ISOLATION_UPPER_MOUNT
    })
```

**修改**:
- `batchsandbox_provider.py` — `_build_pod_spec()` 添加 volume + volumeMount
- `agent_sandbox_provider.py` — 同上

### 6.2 Env 注入

在 execd 容器 env 中添加:

```python
{"name": "EXECD_ISOLATION_UPPER_ROOT", "value": "/var/lib/execd/isolation"},
{"name": "EXECD_ISOLATION_UPPER_MAX_BYTES", "value": "8589934592"},
```

### 6.3 bootstrap.sh

**修改 `components/execd/bootstrap.sh`**:

```bash
if [ -n "${EXECD_ISOLATION_UPPER_ROOT}" ]; then
    mkdir -p "${EXECD_ISOLATION_UPPER_ROOT}"
fi
```

---

## Phase 7: Telemetry (0.5d)

**修改 `pkg/telemetry/record.go`** 或新建 `pkg/telemetry/isolation.go`:

新增指标 (一期):
- `isolation_session_count` (gauge) — 活跃隔离会话数
- `isolation_run_duration_seconds` (histogram) — run 延迟
- `isolation_upper_usage_bytes` (gauge) — upper 目录总占用
- (二期) `isolation_diff_bytes` (counter) — diff 导出字节数

验收: `GET /metrics` 包含 `isolation_*` 指标。

---

## Phase 8: 构建与 CI (1d)

### 8.1 build-bwrap.sh

**新建 `components/execd/scripts/build-bwrap.sh`**:

```bash
#!/bin/bash
set -euo pipefail
BWRAP_VERSION="${BWRAP_VERSION:-v0.10.0}"
BWRAP_REPO="https://github.com/containers/bubblewrap"
OUTPUT_DIR="$(dirname "$0")/../pkg/isolation"

# 需要 musl-gcc
for arch in amd64 arm64; do
    CC=musl-gcc CFLAGS="-static" ./autogen.sh && ./configure --host="${arch}-linux-musl" && make
    cp bwrap "${OUTPUT_DIR}/bwrap_linux_${arch}"
done
```

### 8.2 CI 更新

**修改 `.github/workflows/execd-test.yml`**:

```yaml
- name: Install bubblewrap
  run: sudo apt-get install -y bubblewrap
  if: runner.os == 'Linux'

- name: Run integration tests
  run: go test -v -tags=linux -run Integration ./pkg/isolation/...
  if: runner.os == 'Linux'
```

---

## Phase 9: 测试 (贯穿全流程, 2-3d 集中)

### 9.1 单元测试 (无需 bwrap, 无需 root)

| 包 | 测试文件 | 覆盖 |
|----|---------|------|
| `pkg/isolation/` | `bwrap_test.go` | Argv builder: profile×mode 组合分段顺序, env deny/allow, extra_writable allowlist, `/tmp` 互斥 |
| | `probe_test.go` | 版本解析, capabilities 序列化 |
| | `upper_test.go` | 分配/释放, GC 过期, 大小限制 |
| | `merged_view_test.go` | Stat/ReadDir 在 upper+lower, ro mode 拒绝写, 路径安全 |
| | `commit_test.go` | rsync 正确性 |
| `pkg/web/controller/` | `isolated_session_test.go` | fakeRunner CRUD, SSE streaming, 错误响应 |
| `pkg/web/model/` | `isolated_session_test.go` | 请求验证 (必填字段, 字段类型) |

### 9.2 集成测试 (Linux + bwrap, build tag `integration`)

| 场景 | 验证 |
|------|------|
| 端到端生命周期 | create → run(echo $$ → 1) → get → delete |
| PID 隔离 | 两个会话各自 `echo $$` = 1 |
| `/tmp` 隔离 | 不同会话 `/tmp` 不可见 |
| Overlay CoW | 会话内写入不修改 workspace |
| 文件系统代理 | upload → download 往返; search 合并 |
| 并发 | 两个独立会话并行 run |
| 空闲 GC | 超时自动销毁; run 重置计时器 |
| 不可用降级 | probe 失败 → 所有端点 503 |
| Diff/Commit stub | 返回 503 + error code `not_implemented` |

### 9.3 冒烟测试

**修改 `components/execd/tests/smoke_api.py`** — 新增:

```python
def test_isolated_session_lifecycle():
    # create → run → get → delete
    # capabilities endpoint
    pass

def test_isolated_filesystem_proxy():
    # upload → download → delete → search
    pass

def test_isolated_noop_if_unavailable():
    # 当 bwrap 不可用时
    pass
```

### 9.4 手动验证项

- [ ] 测量 bwrap namespace 冷启动 <1ms
- [ ] 验证 upper 大小限制触发 SIGKILL
- [ ] 验证 commit 在 overlayfs 下正确处理 whiteout/opaque (v1.1)
- [ ] Python/TS/Go SDK 示例端到端跑通

---

## 文件变更总汇

### 新建 (~30 files)

```text
components/execd/pkg/isolation/
  isolator.go              Isolator interface + WrapOptions
  bwrap.go                 bwrap argv builder + Wrap()
  bwrap_test.go            argv 构建测试
  bwrap_linux.go           //go:embed bwrap, Linux
  bwrap_stub.go            !linux stub
  bwrap                    musl static binary (linux/amd64 + arm64)
  probe.go                 启动探测
  probe_test.go            探测测试
  upper.go                 Upper 目录管理 + GC
  upper_test.go            Upper 测试
  seccomp.go               Seccomp BPF 加载
  merged_view.go           Overlay 文件系统视图
  merged_view_test.go      MergedView 测试
  commit.go                Commit stub (二期实现)
  diff.go                  Diff stub (二期实现)

components/execd/pkg/runtime/
  isolated_session.go      isolatedSession struct
  isolated_session_ctrl.go Session CRUD + Runner interface

components/execd/pkg/web/controller/
  isolated_session.go      IsolatedSessionController
  isolated_session_files.go Filesystem proxy handlers

components/execd/pkg/web/model/
  isolated_session.go      Request/response types

components/execd/pkg/telemetry/
  isolation.go             Isolation metrics

components/execd/scripts/
  build-bwrap.sh           Cross-compile bwrap

sdks/sandbox/python/src/opensandbox/models/
  isolated.py              Pydantic models

sdks/sandbox/python/src/opensandbox/adapters/
  isolated_adapter.py      Adapter class

sdks/sandbox/javascript/src/models/
  isolated.ts              Interfaces

sdks/sandbox/javascript/src/services/
  isolated.ts              Service class
```

### 修改 (~19 files)

```text
components/execd/
  pkg/flag/flags.go                新增 flag 变量
  pkg/flag/parser.go               注册 flag + env
  main.go                          嵌入提取 + 探测启动
  pkg/runtime/ctrl.go              新增 isolatedSessionMap + probe
  pkg/web/router.go                注册 /v1/isolated/* 路由组
  pkg/telemetry/record.go          新增隔离指标
  Makefile                         build-bwrap target, test-integration
  bootstrap.sh                     创建 upper root 目录

specs/
  execd-api.yaml                   新 schema + 路径

sdks/sandbox/go/
  types.go, execd.go, sandbox_exec.go   新 types + methods

server/opensandbox_server/services/k8s/
  provider_common.py               isolation-upper emptyDir
  batchsandbox_provider.py         volumes
  agent_sandbox_provider.py        volumes

.github/workflows/
  execd-test.yml                   集成测试 steps
```

---

## 风险跟踪

| 风险 | 缓解 | 状态 |
|------|------|------|
| bwrap CVE | 固定 v0.10.0+, `//go:embed` 随 execd 发布 | ⬜ |
| Upper 磁盘耗尽 | 硬限制 + du check + GC | ⬜ |
| 非 Linux 不支持 | `Available()=false`, 端点 503 | ⬜ |
| MergedView 路径遍历 | `filepath.Clean` + prefix guard | ⬜ |
| (二期) gVisor 无 overlay mount | `commit_supported=false`, diff 仍可用 | 🔵 二期 |
| (二期) Commit 并发写 | per-session Write lock | 🔵 二期 |
| (二期) MergedView whiteout/opaque 正确性 | 集成测试 + overlayfs 内核行为验证 | 🔵 二期 |

---

## 执行顺序 (依赖图)

```
Phase 1 (核心 infra) ✅
  └── Phase 2 (model + router + controller + runtime + FS + GC) ✅
        └── Phase 3 (seccomp + telemetry + spec + 测试补全) ✅
              ├── Phase 4a (Server/K8s 集成)
              ├── Phase 4b (SDK Types)
              └── Phase 4c (Diff/Commit 真实实现)
```

已交付: Phase 1 → 2 → 3 → 4 (全部 SDK + Server + E2E)
遗留: isolated file handler 兼容性 (阻塞 session.files API)、Diff/Commit (二期)
当前分支: osep-0013-phase1-isolation-core

---

## 总工作量

| Phase | 内容 | 状态 |
|-------|------|------|
| 1 | 核心基础设施 (isolation/bwrap/upper/MergedView) | ✅ 完成 |
| 2 | 会话生命周期 (model/router/controller/runtime/FS proxy/GC) | ✅ 完成 |
| 3 | Seccomp + Telemetry + OpenAPI Spec + 70+ 集成测试 | ✅ 完成 |
| — | PR review: TOML config, API 扁平化, VFS 接口, envs, seccomp override | ✅ 完成 |
| 4 | SDK (5 语言) + Server bwrap 分发 + extension + E2E | ✅ 完成 |
| — | Isolated file handler 兼容性 | ⬜ 阻塞 session.files SDK API |
| — | Diff/Commit 真实实现 | ⬜ 二期 |
| — | FilesystemController VFS 迁移 | ⬜ 二期 |
