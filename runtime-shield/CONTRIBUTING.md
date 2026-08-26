# Contributing

```bash
git clone https://github.com/YOUR-ORG/runtime-shield
cd runtime-shield
pip install -e ".[dev]"
pytest && ruff check shield tests && shield test && shield fuzz
```

## The one rule for guard changes

Every detection change needs tests on **both** sides:

- an attack that must be **blocked**, and
- a realistic, legitimate call that must still be **allowed**.

False positives are the failure mode that kills a security tool in production —
a guard that blocks ordinary work gets switched off, and then it protects
nothing. `tests/test_redteam.py` enforces the balance, and `shield test` runs the
same corpus against whatever config is in front of you.

Then run `shield fuzz`. It mutates every blocked attack and reports variants that
still work but are no longer detected — the bypasses your new pattern left open.
`tests/test_fuzz_replay.py::test_the_shipped_policy_has_no_bypasses` holds that
count at zero, and every case in `tests/test_normalize.py` is a payload the
fuzzer once found.

## Adding a guard

1. Subclass `Guard` (inbound) or `OutboundGuard` (outbound) in `shield/guards/`.
2. Add a `Stage` member in `shield/models.py`.
3. Add its config section in `shield/config.py`, defaulting to something safe
   *and* usable with no tuning.
4. Register it in `Shield._inbound` / `Shield._outbound` in `shield/engine.py`.
   Order matters: cheap and decisive first.
5. Add both halves of the tests, plus entries in `ATTACKS`/`SCAN_CASES` in
   `shield/cli.py` if the case is broadly relevant.

Guards must never raise into the request path — the engine catches exceptions and
records them, but a guard that throws is a guard that is not protecting anything.
