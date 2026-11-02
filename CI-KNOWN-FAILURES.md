# Known CI failures — what is currently red and why

> **This file is a marker for agents and for the owner.** Every item below was
> reproduced on a real CI run (2026-11-02) and points at exact `file:line`.
> If you fix one — remove the item here and say so in the commit message.
>
> Context: the repository is built by Jenkins (multibranch project `BalanSir`,
> branch `main`) and by GitHub Actions. Both are red at the time of writing, for
> the reasons below.

---

## 1. `E0603` — private function used from the test module — **open**

**Symptom**

```
error[E0603]: function `set_matches_host` is private
```

Three call sites, crate `balansir-b4`:

- `crates/balansir-b4/src/config.rs:333` — `assert!(crate::engine::set_matches_host(set, "www.youtube.com"));`
- `crates/balansir-b4/src/config.rs:334` — `assert!(crate::engine::set_matches_host(set, "i.ytimg.com"));`
- `crates/balansir-b4/src/config.rs:335` — `assert!(!crate::engine::set_matches_host(set, "example.com"));`

**Definition**

- `crates/balansir-b4/src/engine.rs:406` — `fn set_matches_host(set: &crate::set::B4Set, host: &str) -> bool`
  (private to the `engine` module; the test module in `config.rs` is a sibling
  module and cannot see it).

The production call site inside `engine.rs` itself is fine — only the cross-module
use from `config.rs` is an error. That is why the crate compiles as a library but
fails the moment the workspace test target is built.

**How to close it**

Make the function visible to the crate — `pub(crate) fn set_matches_host(...)` —
or move the assertions into `engine.rs`. Do not make it `pub` unless the API is
meant to be public: the crate is a library with a deliberate surface.

**Verification**

```bash
cargo test -p balansir-b4 --lib
```

---

## 2. Which CI covers what

`BalanSir` has both a Jenkins multibranch job (`BalanSir`, branch `main`) and a
GitHub Actions workflow. The Jenkins job runs the repository's own gate script
first and then `cargo test --workspace`; the GitHub workflow fails on the same
`E0603`, so both agree. Once the visibility fix lands, re-run both.
