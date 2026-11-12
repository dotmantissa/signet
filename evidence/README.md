# Public verification evidence

[`studio-reviewed/`](studio-reviewed/) contains the current executed Studio chain
61999 deployment and test journal. Its [verification result](studio-reviewed/verification-result.json)
and [safety result](studio-reviewed/safety-verification-result.json) record matching
deployed sources, independently agreed assessments, consumer effects and recovery
probes. The [verification summary](remediation-2026-11-11/verification-summary.json)
binds the contract hashes to 239 passing tests and all three successful lint/SDK
checks. `studio-final/` preserves the initial deployment and historical observations.
The corpus is publicly disclosed synthetic evidence authored for these
tests; it asserts no actual economic rights, incident history or issuer status.
Source authority is the configured owner's explicit delegation to the recorded
signing principals.

- `*.operation.json` records the signed operation's public arguments and its
  transaction hash. It contains no signing key.
- `*.receipt.json` records actual finalized executions. Generated assessment,
  finality, certificate and acknowledgement transactions use `-message-` names.
  Check execution results as well as lifecycle status.
- `*.request.json`, `*.relation.json`, `*.consumer.json`, `*.delivery.json`,
  `*.capacity.json`, `*.directory.json` and `*.alias.json` preserve each original
  suite observation before the later recovery state probes.
- `execution-profiles.json` records final validator votes, model metadata,
  provider-reported host statistics and the complete public packet byte counts.
  Selected idle validators are included for transparency and are not counted
  as independently agreeing executions.
- `code-verification.json`, `*.code.json` and `*.schema.json` preserve exact
  deployed GenVM source comparisons and remotely retrieved ABIs. Studio source
  comes from `gen_getContractCode`; the empty `eth_getCode` diagnostic is an EVM
  marker rather than the GenVM source.
- `recovery-probes.json` and `quarantine-probe-checkpoint.json` preserve the later
  translation-case quarantine, retired cluster, retained hold and idempotent
  owner release. The original invoice and incident positive examples remain
  available. Read the probe record before interpreting current deployment state.

`public-sources.json` links immutable original public source bytes and their
authority disclosure. The changed-source test commits to original bytes through
a mutable URL; `studio-final/changed-source-edit.json` records the later edit.
`direct-tests.txt`, `tooling-tests.txt`, `lint-results.json` and the runtime probe
files document local checks and baseline runtime compatibility.

Prior setup/release journals remain local recovery records. They are excluded
from Git; `studio-reviewed/` is the current published verification deployment. Credentials,
local instruction files, recovery checklists and process logs are also excluded.
