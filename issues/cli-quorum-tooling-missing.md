# rawstor-cli: no operator tooling for the quorum model

## Where

`cli/` — only has `create`, `remove`, `show`, `testio` subcommands
(`cli/main.c`). No equivalent of `force-open`, `status`, or `resolve`.

## Problem

The mirror quorum design (`docs/mirroring.md`) deliberately refuses to
auto-start below a strict majority, and deliberately refuses to auto-pick a
winner on split brain (case F9) — both by design, to exclude those failure
modes structurally rather than guess. But both cases are explicitly meant to
have a **manual** escape hatch for an operator who understands the
consequences:

- **Below-quorum open**: currently there is no way to open a mirrored object
  at all if it doesn't have a reachable majority, even if an operator knows
  it's safe to proceed (e.g. planned maintenance took most members down).
- **Split brain (F9)**: `docs/mirroring.md` describes the intended recovery
  as `rawstor-cli resolve --winner=<uri>` (pick a winner, bump its sync_id,
  full-resync the loser) — this command doesn't exist yet.
- **Status inspection**: there's no way to ask "what state is each mirror
  member in right now" (`IN_SYNC`/`STALE`/`SYNCING`, epoch, sync_id) without
  reading server-side metadata directly (`zfs get`/`lvs`/inspecting a `.spec`
  file by hand). A `rawstor-cli status` command was the intended interface.

Without these, an operator who hits below-quorum-open or split-brain has no
supported way to recover a mirrored object short of manual surgery on the
underlying storage.

## Suggested fix

Add the three subcommands as originally scoped in `docs/mirroring.md`'s
protocol/code-change map:

- `rawstor-cli force-open --target=<...>` — open below quorum, explicit
  operator opt-in (maps to a library-level "force" path that doesn't exist
  yet either — would need a corresponding `RawstorOpts`/API addition).
- `rawstor-cli status --target=<...>` — report per-member state/epoch/
  sync_id/reachability (needs `rawstor_object_meta` per member, which already
  exists as a building block).
- `rawstor-cli resolve --target=<...> --winner=<uri>` — the F9 recovery path:
  bump the winner's sync_id/epoch, mark it authoritative, trigger a full
  resync of the other member(s).

## Note

Scoped as v1 follow-up work in `docs/mirroring.md` from the start (not a
regression); listed here as a tracked gap rather than a defect. Not started.
