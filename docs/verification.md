# Verification record

This record describes the initial release. Current deployment addresses, exact source comparisons, consensus/callback chains and live safety probes are preserved in [studio-reviewed](../evidence/studio-reviewed), with the current [verification result](../evidence/studio-reviewed/verification-result.json) and [safety result](../evidence/studio-reviewed/safety-verification-result.json).

The initial integration deployment used hosted GenLayer Studio (`studionet`), chain
61999, and the pinned runner
`py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`.
Deployment addresses, signing principals, contract source hashes and the source
checkout commit are recorded in
[deployment.json](../evidence/studio-final/deployment.json).
`initial_deployment_source_commit` identifies the initial deployed contract
checkout; `source_commit` identifies the checkout used to resume the suite.
Exact byte comparisons provide the final source binding.

## Reproduce

Install the pinned dependencies from `requirements.txt`, then run:

```bash
.venv/bin/genvm-lint check contracts/signet.py
.venv/bin/genvm-lint check contracts/receivable.py
.venv/bin/genvm-lint check contracts/incident.py
.venv/bin/pytest tests/direct -v
.venv/bin/python -u -m scripts.run_batch
.venv/bin/python -u -m scripts.verify_studio --state-probes
```

The network commands use three distinct signing keys loaded through
`SIGNET_DEPLOYER_KEY`, `SIGNET_RECEIVABLE_KEY` and `SIGNET_INCIDENT_KEY`, or the
ignored secure local credential source. The source-change probe additionally
uses the corpus owner's GitHub credential. Keys are never transaction arguments
or evidence fields. The checked-in operation journal resumes the recorded
deployment; a fresh deployment requires a fresh journal and matching synthetic
source authority disclosure.

## Deterministic verification

All three contracts pass GenVM AST and SDK semantic checks. The initial direct
suite passed 101 tests; see [direct-tests.txt](../evidence/direct-tests.txt).
Four additional tooling tests pass for rate rejection, receipt identity, cached
execution failure and polling past a cached pending receipt; see
[tooling-tests.txt](../evidence/tooling-tests.txt). Run them with
`.venv/bin/python -m pytest tests/tooling -v`.

The contract tests cover authenticated delivery, independent consumer ownership,
pending capacity, quarantine, source revisions, supersession, reordered
callbacks, bounded aliases and cross-revision DISTINCT witnesses. Direct mode
uses explicit web/model fixtures and a test-only isolated multi-contract router.
It cannot prove network finality.

Validator probes explicitly invoke the captured validator with altered leader
results. They reject substantive wrong answers, missing exceptions, invented
citations, changed bytes, altered identifying facts, transient model errors and
VM errors. This is separate from the real network verification below.

## Real network verification

The corpus is [public synthetic evidence](../evidence/public-sources.json).
The bytes and model calls are real during the network suite. No actual
receivable, incident or organizational authority is asserted. Each source is
attested by its configured Studio signing principal, and the public disclosure
describes the owner-delegated test channel.

The third deployment, `organization_policy_receiver`, is an obligation consumer
bound to an organization policy for a negative schema-compatibility probe. Both
organization decisions remain available from Signet, while this incompatible
consumer quarantines their certificates and retains its holds. An organization
consumer would need to define its own consequence and explicitly require the
organization schema.

The suite checks reissued invoices, distinct monthly obligations, renamed and
recurring incidents, organizations with matching names and different official
IDs, incomplete identification, instructions embedded in evidence, controlling
exceptions, translation, changed source bytes and forged span commitments.

All 11 requests reached the application finality barrier with the expected
decisions and acknowledged consumer outcomes. Every substantive assessment has
at least two agreeing validator execution receipts, and `leader_only` is false.
Selected idle validators are recorded but excluded from the agreement count.
The generated assessment, finality, callback and acknowledgement transactions
all finalized with successful execution.

See [suite-result.json](../evidence/studio-final/suite-result.json),
[execution-profiles.json](../evidence/studio-final/execution-profiles.json), and
the per-case operation, receipt, relation, consumer and delivery files in
[studio-final](../evidence/studio-final). Incident directory observations also
verify the actual canonical ID for SAME and retained historical ID for DISTINCT.
All three SAME aliases were verified as active before the later recovery probe.

At that release, all four deployed sources matched its checkout byte for byte; see
[code-verification.json](../evidence/studio-final/code-verification.json). Studio
returns GenVM source as base64 through `gen_getContractCode`; `eth_getCode`
returns an empty EVM marker for these addresses. The matching source responses
and deployed schemas are preserved alongside the hashes.

| Case | Relation | Consumer result | Agreeing validators |
| --- | --- | --- | --- |
| invoice-reissue | SAME | PERMITTED | 2 |
| invoice-next-month | DISTINCT | REFUSED_DISTINCT | 3 |
| incident-renamed | SAME | PERMITTED | 3 |
| incident-recurring | DISTINCT | REFUSED_DISTINCT | 3 |
| organization-same-name | DISTINCT | QUARANTINED | 2 |
| name-only | UNKNOWN | QUARANTINED | 2 |
| injected-instruction | DISTINCT | REFUSED_DISTINCT | 2 |
| controlling-exception | DISTINCT | REFUSED_DISTINCT | 2 |
| translation | SAME | PERMITTED | 2 |
| changed-source | UNKNOWN | REFUSED_UNRESOLVED | 2 |
| forged-span | UNKNOWN | REFUSED_UNRESOLVED | 2 |

## Recovery and resource limits

The earlier RPC interruption is preserved in local journals. Hosted Studio
returned `-32029`, reporting 30 requests per minute. The runner paces all clients
in one process at a minimum three seconds per RPC and retries explicit rate
rejections after 45 seconds. Recorded operation hashes prevent duplicate
broadcasts when resuming. Separate concurrent runner processes do not share the
in-process pacer.

The executed [recovery probes](../evidence/studio-final/recovery-probes.json)
repeat an existing publish, reconcile its acknowledgement,
quarantine a synthetic positive relation, verify that the permitted operation
becomes quarantined while its hold remains, and release that hold twice from
its owner. The verifier checkpoints quarantine observations before release.
The repeated publish and reconcile left the delivery at one broadcast attempt.
Quarantine retired the translation alias cluster, restored both historical IDs,
and changed its consumer operation to QUARANTINED while retaining 12,500 minor
units. Two owner release calls finalized successfully; held capacity then became
zero. The final deployment preserves the original suite observations and the
later recovery-probe state separately. The invoice-reissue and incident-renamed
positive examples remain active.

The final [verification result](../evidence/studio-final/verification-result.json)
records all 11 real-consensus cases, exact source matches and successful recovery
probes.

The configured byte, prompt, retry, witness and cluster ceilings are admission
bounds. The synthetic corpus measures small complete packets; it does not
establish that arbitrary inputs succeed at every ceiling. Studio is gasless,
and its reported zero gas values do not establish a production gas budget.
Participant processing times and host statistics are provider-reported
measurements, not independent CPU or memory profiling. No application model
completion-token limit is supplied by this pinned SDK; response limits are
checked after receipt.
