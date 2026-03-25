# SDK Dev Agent

## Scope

Use this guide for changes in:

- `sdks/sandbox/*`
- `sdks/code-interpreter/*`
- `sdks/mcp/*`
- `specs/*` when the change affects SDK contracts

Do not use this guide for:

- `server/*`
- `components/execd/*`
- `sandboxes/*` unless the task is explicitly about SDK integration

## SDK Map

- Python sandbox: `sdks/sandbox/python`
- Python code interpreter: `sdks/code-interpreter/python`
- JavaScript sandbox: `sdks/sandbox/javascript`
- JavaScript code interpreter: `sdks/code-interpreter/javascript`
- Kotlin sandbox: `sdks/sandbox/kotlin`
- Kotlin code interpreter: `sdks/code-interpreter/kotlin`
- C# sandbox: `sdks/sandbox/csharp`
- C# code interpreter: `sdks/code-interpreter/csharp`
- Sandbox lifecycle spec: `specs/sandbox-lifecycle.yml`
- Execd/code execution spec: `specs/execd-api.yaml`

## Generated Code

Do not manually edit generated code.

Generated or generator-owned locations:

- Python OpenAPI client: `sdks/sandbox/python/src/opensandbox/api/**`
- JavaScript OpenAPI types: `sdks/sandbox/javascript/src/api/*.ts`
- Kotlin generated API code: `sdks/sandbox/kotlin/sandbox-api/build/generated/**`

Handwritten code belongs in adapters, services, facades, converters, and stable SDK models.

Use generated clients for normal request/response APIs. Use handwritten transport only for streaming or protocol-specific paths such as SSE.

## Code Generation

When `specs/execd-api.yaml` or `specs/sandbox-lifecycle.yml` changes:

1. Regenerate affected SDK code.
2. Update handwritten adapters or converters.
3. Update tests.
4. Validate every affected language family.

Generation commands:

Python sandbox:

```bash
cd sdks/sandbox/python
uv sync
uv run python scripts/generate_api.py
```

JavaScript sandbox:

```bash
cd sdks/sandbox/javascript
pnpm run gen:api
```

Kotlin sandbox API:

```bash
cd sdks/sandbox/kotlin
./gradlew :sandbox-api:generateLifecycleApi :sandbox-api:generateExecdApi :sandbox-api:generateEgressApi
```

## Local Commands

### Python

Sandbox SDK:

```bash
cd sdks/sandbox/python
uv sync
uv run python scripts/generate_api.py
uv run ruff check
uv run pyright
uv run pytest tests/ -v
uv build
```

Code interpreter SDK:

```bash
cd sdks/code-interpreter/python
uv sync
uv run ruff check
uv run pyright
uv run pytest tests/ -v
uv build
```

### JavaScript

Workspace install:

```bash
cd sdks
pnpm install --frozen-lockfile
```

All JS SDKs:

```bash
cd sdks
pnpm run lint:js
pnpm run typecheck:js
pnpm run build:js
pnpm run test:js
```

Per package:

```bash
cd sdks/sandbox/javascript
pnpm run gen:api
pnpm run lint
pnpm run typecheck
pnpm run build
pnpm run test
```

```bash
cd sdks/code-interpreter/javascript
pnpm run lint
pnpm run typecheck
pnpm run build
pnpm run test
```

### Kotlin

Sandbox SDK:

```bash
cd sdks/sandbox/kotlin
./gradlew spotlessApply :sandbox:test
```

Code interpreter SDK:

```bash
cd sdks/code-interpreter/kotlin
./gradlew spotlessApply :code-interpreter:test
```

If Kotlin `code-interpreter` must consume the latest local sandbox SDK:

```bash
cd sdks/sandbox/kotlin
./gradlew publishToMavenLocal
```

```bash
cd sdks/code-interpreter/kotlin
./gradlew -PuseMavenLocal spotlessApply :code-interpreter:test
```

### C#

Sandbox SDK:

```bash
cd sdks/sandbox/csharp
dotnet build OpenSandbox.sln --configuration Release /warnaserror
dotnet test tests/OpenSandbox.Tests/OpenSandbox.Tests.csproj --configuration Release
```

Code interpreter SDK:

```bash
cd sdks/code-interpreter/csharp
dotnet build OpenSandbox.CodeInterpreter.sln --configuration Release /warnaserror
dotnet test tests/OpenSandbox.CodeInterpreter.Tests/OpenSandbox.CodeInterpreter.Tests.csproj --configuration Release
```

## Checks

- Single-package change: run that package's lint/static checks and tests.
- Shared behavior or model change: run affected packages across affected language families.
- Spec change: regenerate code, update handwritten layers, and run affected SDK checks across languages.
- Add a regression test for every bug fix.
- Prefer tests for request mapping, response conversion, error mapping, streaming behavior, header propagation, reconnect behavior, and resource cleanup.

## Boundaries

Always:

- keep generated and handwritten code separate
- update tests with behavior changes
- follow the existing SDK layering; keep changes in the correct facade, service, adapter, converter, or model layer

Ask first:

- public breaking changes
- large cross-language refactors
- intentional behavior drift between languages

Never:

- patch generated output as the only fix
- change SDK public behavior without tests
- mix unrelated SDK and non-SDK work in one change without a strong reason
