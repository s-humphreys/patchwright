# Example configuration

These files are **generic, editable examples** — a starting point, not a
prescription. patchwright bakes in no ownership taxonomy or organization
specifics; all of that lives here as CEL rules you own.

- [`ownership.yaml`](ownership.yaml) — attribute each workload to an owner
  (first match wins).
- [`policy.yaml`](policy.yaml) — decide what is actionable, at what priority,
  and what to suppress.

See the [root README](../README.md#writing-rules) for the rule schema and the
variables available to expressions.

## Your real configuration

Keep organization-specific rules and scanner exports out of version control.
The repository gitignores a `local/` directory for exactly this — put your real
config and Rapid7 export there and point the CLI at them:

```sh
patchwright assess \
  --input local/export.csv \
  --config local/config/
```
