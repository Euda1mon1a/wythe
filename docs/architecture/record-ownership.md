# Experimental record-ownership workflow

This workflow investigates one claim: **one user cannot modify another user's
record**. It has two separate commands. Source inspection collects evidence from
one selected Python handler. The demonstration executes only Wythe's shipped,
synthetic FastAPI examples against fresh in-memory SQLite databases.

Neither command is an automated security audit of a repository. Existing
architecture edges and blast radius do not prove input flow, authorization,
exploitability, or safe deletion. Red/blue/purple operational modes, live target
testing and general exploit generation are not implemented by this feature.

## Inspect a hypothesis without executing the target

```bash
wythe security ownership /path/to/repo \
  --handler backend/app/api/records.py:update_record \
  --record record --principal user.id --owner-field owner_id \
  --json ownership-evidence.json
```

The selected names describe the hypothesis; Wythe does not infer that `user.id`
is trustworthy or that `record` still refers to the object originally loaded.
The report contains the exact source-byte SHA-256, relative path, handler name,
line numbers, AST expressions, and explicit unknowns. JSON is printed to stdout;
`--json` also creates a new file and refuses to overwrite an existing receipt.

The initial Python extractor observes:

- Local FastAPI route decorators on a module-level `FastAPI`/`APIRouter` receiver.
- `Depends(...)` declarations, including aliases and `Annotated` parameters.
- A selected variable assigned from `Session.get(...)` or awaited
  `AsyncSession.get(...)`, when the session parameter has a recognized annotation.
- Assignments, augmented assignments and deletions of the selected record's
  attributes; declared session operations such as `commit`, `flush` and `delete`.
- Equality/inequality comparisons between the selected owner and principal.
- The narrow mismatch branch `if record.owner_id != user.id:` followed by a
  single `raise HTTPException(403/404)`. This is a source observation, including
  when it appears after a write, inside a caught exception, or under a condition.

Evidence placement is **direct**, **conditional**, or **inactive**. Literal false
branches remain visible as inactive evidence; bodies of nested function/class
definitions are excluded. These labels describe syntax, not execution. Line
order does not establish that a check runs before every write or cannot be
bypassed. Absence of a recognized check is not a confirmed vulnerability.

**Every static report has `invariant_result: "unknown"`.** Helpers, imports,
middleware, decorators, principal authentication, rebinding, dynamic writes,
query filters, model-to-table resolution, mounted URLs, transactions and
database policies are not followed or verified. The command is intentionally
separate from the existing architecture gate and its rule severity catalog.

Source reads accept one regular `.py` file, up to 1 MiB, under the selected root.
They reject path traversal, symlink components and non-regular files, and use
descriptor-relative opens on supported operating systems (Linux/macOS). They
fail closed when those filesystem primitives are unavailable. The command does
not import the target, initialize Wythe's database, invoke a subprocess, contact
an endpoint or inspect a target database. Review source excerpts before sharing
the JSON: it is local evidence, not an automatically sanitized public report.

## Demonstrate a failure, repair it, and retain the regression

```bash
wythe security ownership-demo --json ownership-demo.json
```

This command takes **no target path, URL, credentials, plugin or test command**.
It imports the two fixed routers bundled in `wythe_examples` and uses an
in-process ASGI client. It never starts a listening server or sends a network
request. The examples cannot obtain a database outside the harness: their
default session dependency raises an error.

The vulnerable handler loads a record by ID and updates it without comparing
owners. The repaired handler adds exactly this rejection before mutation:

```python
if record.owner_id != user.id:
    raise HTTPException(status_code=403, detail="Different owner")
```

Both variants run the same eight cases, with a new database for **every** case:

| Case | Expected response | Expected database effect |
| --- | --- | --- |
| Each of two users updates their own record | 200 | Only that record's title changes |
| Each user attempts to update the other user's record | 403 | Both records unchanged |
| Missing identity | 401 | Both records unchanged |
| Unknown identity | 401 | Both records unchanged |
| Missing record | 404 | Both records unchanged |
| Attempt to supply an owner field in the request body | 422 | Both records unchanged |

Each case compares the status and **all record IDs, owner IDs and titles**, read
through a new database session after the response. Returning 403 after a write
does not pass. The vulnerable example must fail exactly the two cross-owner
cases. All eight repaired cases must pass. A regression in the repair makes the
command exit nonzero; an error does not become a passing or empty result.

The result records the cases, expected/observed records and responses, example
source hashes, Wythe version, source evidence for both handlers, and limits.
`holds_for_tested_cases` applies only to the shipped examples. It says nothing
about another repository or untested concurrency, roles, endpoints, database
policies or detection telemetry. The fixed public demo tokens are fixture
identities, not production authentication guidance. Hashes identify content;
they do not make the JSON a signed or tamper-evident audit ledger.

## Exit codes and regression ownership

| Command | 0 | 1 | 2 |
| --- | --- | --- | --- |
| `security ownership` | Evidence collected; invariant still unknown | Unused | Invalid selection, unsupported read, parse or output error |
| `security ownership-demo` | Expected vulnerable failures and repaired successes observed | Demonstration/regression failed | Execution or output error |

The regression lives in `backend/tests/test_record_ownership.py`. CI runs it
serially with the existing suite. Release validation also runs the demonstration
from the built wheel to verify packaging. The example application is a separate package
so its intentionally vulnerable routes are not mistaken for Wythe's production
API during self-dogfood scanning.

For an authorized application assessment, use the source report to choose a
reviewed application test. Adapt the two-identity/state-readback pattern in that
application's isolated test environment and retain its repair regression there.
Wythe does not currently execute arbitrary target tests or promote an external
test report to a verified security finding.
