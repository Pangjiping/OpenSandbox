# OSEP-0013 Phase 1 — Remaining Review Issues

## Security Issues

### S1. [P1] Upper root hiding incomplete — cross-session data leak
- **File**: `components/execd/pkg/isolation/bwrap.go:79-83`
- **Problem**: `filepath.Dir(opts.UpperDir)` only hides `/var/lib/execd/isolation/<id>`, but the parent `/var/lib/execd/isolation/` remains visible through `--ro-bind / /`. Session processes can read other sessions' upper directories.
- **Fix**: Hide `filepath.Dir(filepath.Dir(opts.UpperDir))` to cover the entire upper root.

### S2. [P2] Symlink traversal on MergedView reads
- **File**: `components/execd/pkg/isolation/merged_view.go:146-173`
- **Problem**: `Open()`, `ReadFile()`, `Stat()` follow symlinks via `os.Open`/`os.ReadFile`/`os.Stat`. If a session process creates `upper/x -> /etc/shadow`, MergedView reads it with execd's privileges, leaking host files. `rejectSymlink()` exists but is only called in write paths.
- **Fix**: Add `rejectSymlink()` checks to `Open()`, `ReadFile()`, and `Stat()` for upper paths.

### S3. [P2] Chmod mutates lower (original workspace) files
- **File**: `components/execd/pkg/isolation/merged_view.go:343-361`
- **Problem**: When a file exists only in lower, `Chmod()` falls through to `os.Chmod(lowerPath)`, directly modifying the original workspace and breaking isolation.
- **Fix**: Copy-up to upper before chmod when file only exists in lower.

## Functional Issues (SDK Compatibility)

### F1. [P2] Search returns `[]string`, SDKs expect `FileInfo[]`
- **File**: `components/execd/pkg/web/controller/isolated_session_files.go:84-89`
- **Problem**: Normal `/files/search` returns `FileInfo` objects. Isolated search returns plain path strings. SDK adapters that parse FileInfo will break.
- **Fix**: Return `FileInfo` objects from `SearchFiles()`, matching the normal file API contract.

### F2. [P2] Search ignores `path` query parameter
- **File**: `components/execd/pkg/web/controller/isolated_session_files.go:73-90`
- **Problem**: The handler ignores the `path` query and always searches the entire workspace. SDK callers expect scoped search.
- **Fix**: Pass `path` query to `MergedView.Search()` as the root directory.

### F3. [P2] Rename reads from query params, SDK posts JSON body
- **File**: `components/execd/pkg/web/controller/isolated_session_files.go:187-205`
- **Problem**: SDK adapters POST a JSON body (`[{old_path, new_path}]`), matching the normal `/files/mv` contract. This handler reads from query params and ignores the body.
- **Fix**: Read rename requests from the JSON body.

### F4. [P2] Replace reads from query params, SDK posts JSON body
- **File**: `components/execd/pkg/web/controller/isolated_session_files.go:229-252`
- **Problem**: Same as F3 — SDK adapters POST JSON body for replace. Handler reads from query params.
- **Fix**: Read replace requests from the JSON body.

### F5. [P2] Mkdir reads from query params, SDK posts JSON body
- **File**: `components/execd/pkg/web/controller/isolated_session_files.go:254-268`
- **Problem**: Same as F3 — SDK adapters POST JSON body for mkdir. Handler reads from query params.
- **Fix**: Read mkdir requests from the JSON body.

### F6. [P2] Delete contract uses query params, spec defines JSON body
- **File**: `components/execd/pkg/web/controller/isolated_session_files.go:171-185`
- **Problem**: Handler uses `QueryArray("path")`, but the OpenAPI spec (`execd-api.yaml:1372`) defines a JSON request body. Generated SDK clients will POST a body.
- **Fix**: Accept paths from either query params or JSON body to match spec.

## Low Priority

### L1. [P2] Rename doesn't create whiteout for lower source
- **File**: `components/execd/pkg/isolation/merged_view.go:301-341`
- **Problem**: After renaming a lower-only file (copy-up + rename in upper), the lower source is still visible through MergedView reads. No `.wh.` file is created to mask it.
- **Fix**: Create a `.wh.<name>` whiteout file after rename to hide the lower source.

### L2. [P2] Remove doesn't create whiteout for lower-only files
- **File**: `components/execd/pkg/isolation/merged_view.go:241-266`
- **Problem**: Returns error for lower-only files ("cannot remove from read-only workspace lower"). Should create a whiteout to properly mask the file.
- **Fix**: Create `.wh.<name>` whiteout instead of returning error.

### L3. [P2] RemoveAll only removes upper, lower still visible
- **File**: `components/execd/pkg/isolation/merged_view.go:268-283`
- **Problem**: `RemoveAll` only calls `os.RemoveAll(upper)`. Lower entries reappear in ReadDir/Stat.
- **Fix**: Create whiteout entries for lower-only files within the removed tree.
