# Open WebUI source audit

Target: [open-webui/open-webui](https://github.com/open-webui/open-webui/tree/b0e6098e940942281d9c83f3529ea117287a3a22), pinned at `b0e6098e940942281d9c83f3529ea117287a3a22`.
Scanner: Wythe 0.1.7. Profile: `fastapi-sveltekit` (experimental).

This was a source-only audit. The target application, dependency installers,
database and services were not executed or changed. No upstream bug report was
filed: the inspected candidates did not meet the project's requirement for a
reproduction on both the latest release and current development branch.

## Repairs supported by this audit

- Bound static import/re-export matching to declaration syntax. The previous
  regex stalled on exported Svelte props followed by whitespace from blanked
  markup, and could consume a side-effect import together with a later export.
  A subprocess timeout regression covers both props and incomplete star exports.
- Discover a unique named FastAPI package under the backend root when there is
  no conventional `app/`. The package needs an initializer and a `main.py` or
  `app.py` containing a call to an imported FastAPI constructor. Ambiguous layouts
  are reported instead of guessed; target modules are never imported.
- Keep repository operations beside ORM declarations in `models/` visible as
  mechanisms. Pure model/schema declarations remain caller-only. Literal dead
  branches and annotation-only references do not promote a model to a service.
- Recognize Svelte clients in `apis/`, and recognize the `{alt}` image attribute.
- Stop converting arbitrary `/api/...` string literals into GET requests. The
  target's external terminal wrapper had produced a false missing-route finding,
  while a configuration path string had produced 11 unsupported cross-tier chains.
- Qualify absent inbound callers as absent discovered static references. They do
  not establish safe removal, including for framework-invoked migration modules.

## Observed coverage

The repaired scan finds 49 ORM tables, 2 Redis stores, 38 route modules, 274 other
backend modules, and 832 display modules (49 pages). The inventory has 5,395
static graph edges and **zero complete cross-tier chains**. These counts describe
extraction, not production execution or architecture quality. The 379 rule
candidates are not 379 confirmed defects.

The named chat flow was checked in the graph and source:

| Segment | Observed evidence |
| --- | --- |
| `/c/[id]` page to `Chat.svelte` | Static component import |
| `Chat.svelte` to `lib/apis/chats/index.ts` | Static API client import |
| Chat client to `GET /api/v1/chats/{id}` | Missing: imported URL prefix is unresolved |
| `routers/chats.py` to `models/chats.py` | Static repository import/call evidence |
| `models/chats.py` to `chat` | Module-level ORM read and write evidence |

The repository module contains many operations. Its read/write edges do not
prove that each individual handler performs every operation in that module.

## Remaining work

- [Imported URL constants (#39)](https://github.com/Euda1mon1a/wythe/issues/39):
  resolve statically known same-origin prefixes without guessing dynamic hosts
  or ignoring local shadowing.
- [Opaque component accessible names (#40)](https://github.com/Euda1mon1a/wythe/issues/40):
  do not assume that an uppercase self-closing component is an icon. The target's
  `ModelSettingsLabel` renders text and currently triggers a false positive.
- [Nested Alembic discovery (#32)](https://github.com/Euda1mon1a/wythe/issues/32#issuecomment-6860178944):
  the target's `open_webui/migrations/versions` directory remains outside the
  truth adapter's migration coverage. This audit adds an example to existing work.
- Svelte layouts, server modules, custom request wrappers and function-level
  reachability remain outside the display adapter's coverage. The report names
  these limitations; it must not be read as a clean bill of health for the target.

The patch includes synthetic regression fixtures for these repaired behaviors.
Large source snapshots, raw scan reports and machine-specific execution receipts
are not part of the product repository.
