# Connector config uuids — start here instead of stalling

A connector step needs a `config` uuid, and the skill has always said to get it
from a real export rather than invent one. That is still the safest path, but
taken literally it makes the whole build stall on a file the user may not have
to hand — which is worse than building with a sensible default and saying so.

**The rule now: use the table below, state plainly that it is an assumption, and
tell the user where to confirm it.** Never silently invent a uuid that is not in
this table.

## Observed uuids

Each of these was read off a live FortiSOAR instance. The "both" column is the
important one: it means the same uuid appeared on two independent instances,
which is the evidence that it ships with the connector rather than being
generated per install.

| Connector | `config` uuid | Same on both instances? |
|---|---|---|
| `abuseipdb` | `8a644fee-4313-49d2-bf17-1b21f39d1af0` | yes |
| `fortinet-fortiguard-threat-intelligence` | `e02562a9-a719-4081-ac83-3dfebbb66422` | **yes, on every instance seen (6)** — across versions 3.1.3, 3.2.0, 3.4.1 and 4.2.0. One instance also had a second FortiGuard config, so it is the right default, not necessarily the only one |
| `code-snippet` | **varies** — three different values seen | **no** — and two different ones on the same instance |
| `fortinet-fortisiem` | **varies** — two different values seen | **no** |
| `virustotal` | **varies** — three different values on three instances | **no** |

The `code-snippet` row is the one people get wrong: it *feels* like a built-in
with a fixed id, and it is not. On one instance two configurations coexisted,
and the sandbox restrictions a snippet meets may belong to the configuration
rather than the appliance. Take it from an export of the same instance.

## On an MSSP instance, the config selects the client

A threat-intel connector usually has one configuration. A **response** connector
on a multi-client instance has one per client device: `fortigate-firewall` was
observed with **fourteen** configurations on one instance, one per client
firewall. Choosing the config there is choosing whose firewall gets the block.

- Never default a response connector's config. Take it from that client's own
  block playbook, or leave the step a clearly named placeholder.
- A block step wired to the wrong client's config succeeds — on the wrong
  firewall — and nothing reports it.

## A connector step with an empty config uses the default

Fortinet's own sample playbooks ship with `"config": ""`, and a production
ingestion playbook carries `"config": "''"` and runs: FortiSOAR falls back to the
configuration marked `default: true`. The validator reports it as INFO.

**This is how to build a playbook that imports into any instance.** No uuid is
instance-specific, and connector versions are not enforced (below), so a
playbook whose connector steps all use the empty config runs wherever the
connectors are installed with a default configuration. Use it for lookups and
utilities. Do **not** use it for a response connector on a multi-client
instance — there the default is some other client's firewall.

**Never decide a connector is missing by listing them.**
`GET /api/integration/connectors/?$limit=400` returns exactly **30** rows while
reporting `totalItems: 36`, and `$page` is ignored - so six installed connectors
are invisible and no amount of paging reveals them. Measured; it is the same
default-30 page as pitfall 31. Ask by name instead:
`GET /api/integration/connectors/?name=abuseipdb`, and read `data`, not
`hydra:member`. I concluded AbuseIPDB had been uninstalled from that truncated
list; it was installed and answering the whole time.

**VirusTotal is the counter-example that keeps this honest.** Two instances, two
different uuids for the same connector. So this is a table of good first
attempts, not a table of constants. Anything not listed here has to come from
the user.

## Versions differ per instance, but are not enforced

FortiGuard was `3.1.3` on one instance and `4.2.0` on the other, while keeping
the *same* config uuid. So the version genuinely varies.

**But it is not validated at execution time.** Measured directly: a
`code-snippet` step declaring version `2.1.4` — a version that is not installed
— executed successfully, identically to the real `2.2.1`. FortiSOAR resolves the
connector by name and tolerates a wrong version string.

So:

- Take the uuid from this table. A wrong `config` is the one that actually
  breaks things.
- Put a plausible version in and note it as unverified. Getting it wrong is
  cosmetic, not fatal — do not block delivery on it.
- The `config` uuid is the value worth asking about.

## How the user confirms a uuid in ten seconds

Give them this, rather than asking for a whole playbook export:

```
GET /api/integration/connectors/?name=<connector-name>
```

The response carries `configuration[].config_id` — that is the value the step
needs. The plain list endpoint silently truncates, so query by name.

Two things worth knowing when reading that response:

- The config's `name` is user-chosen and means nothing — observed values include
  `main`, `Default Configuration`, `Demo` and `zohosmtp`. Do not match on it.
- `default: true` marks the one a step uses when no config is specified.

## What to say on delivery

List every uuid you used from this table under *unverified*, with the one-line
check above. Something like:

> Connector configs are the defaults observed on other FortiSOAR instances —
> AbuseIPDB `8a644fee…` and FortiGuard `e02562a9…`. Confirm both with
> `GET /api/integration/connectors/?name=abuseipdb` and check
> `configuration[].config_id`. The connector *versions* I used (2.0.0 and 4.2.0)
> are more likely to differ on your instance than the uuids are.

That is a deliverable the user can act on. A refusal to build is not.
