.PHONY: sync sync-dev test test-kubernetes-mini test-network-policy test-sandbox test-manager test-code lint fmt

sync:
	uv sync

sync-dev:
	uv sync --group dev

test:
	uv run pytest

test-kubernetes-mini:
	uv run pytest \
		--ignore=tests/test_code_interpreter_e2e.py \
		--ignore=tests/test_code_interpreter_e2e_sync.py

# 临时：只跑 async test_01aa network policy 用例（该用例在 Kubernetes 下不再 skip，便于单独调试）。
test-network-policy:
	uv run pytest tests/test_sandbox_e2e.py::TestSandboxE2E::test_01aa_network_policy_get_and_patch

test-sandbox:
	uv run pytest tests/test_sandbox_e2e.py

test-manager:
	uv run pytest tests/test_sandbox_manager_e2e.py

test-code:
	uv run pytest tests/test_code_interpreter_e2e.py

lint:
	uv run ruff check tests

fmt:
	uv run ruff format tests
