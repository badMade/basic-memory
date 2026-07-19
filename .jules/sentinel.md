# Sentinel Journal — Basic Memory

Critical, codebase-specific security learnings only. Not a work log.

## 2026-07-18 - Path-boundary validation is enforced at the edges, not at the write sink

**Vulnerability:** `FileService.write_file`/`move_file` join a caller-supplied
relative path straight onto `base_path` (`base_path / path`) with no
containment check. Project-boundary validation (`validate_project_path`) is
applied only at the MCP tool layer (`write_note`, `move_note`, `read_content`)
and some v2 API routers — never at the shared filesystem sink. Two callers
bypassed the edge checks entirely:
  1. `importers/memory_json_importer.py` built `file_path` from the untrusted
     entity `name`/`entityType` without `clean_filename()` (the three sibling
     importers all sanitize). `..` segments reached `write_file` → arbitrary
     `.md` create/overwrite. Reachable via CLI **and** the HTTP import endpoint.
  2. `schemas/base.py` `Entity.directory` is sanitized by
     `sanitize_for_directory`, which filtered characters but did **not** drop
     `..` segments, so the computed `file_path` could traverse on the raw v2
     `create_entity`/`update_entity` API path (the MCP `write_note` tool guards
     `directory`, but the HTTP API did not).

**Learning:** Security here was layered at the entrypoints (tools/routers), so
any new caller that reaches `FileService` directly inherits no protection. The
`Entity.file_path` computed property makes the directory sanitizer the single
choke point for every note write, so traversal has to be neutralized there too.

**Prevention:** Fail closed at the sink. `FileService.write_file`/`move_file`
now resolve the target and reject anything not `is_relative_to(base_path)`, and
`sanitize_for_directory` drops `.`/`..` segments. When adding a writer, assume
the path is hostile — do not rely on an upstream tool having validated it.
