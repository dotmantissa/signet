# Signet

Signet resolves whether two public records refer to the same economic obligation, incident or organization. A signet marks identity across differently presented records. The contract keeps the records' original IDs, records source-grounded SAME, DISTINCT or UNKNOWN relations, and permits bounded alias merges only when every required witness agrees.

GenLayer consensus governs the identity judgment. Each participant retrieves the complete committed source packet and independently extracts the schema's identifying facts and controlling exceptions. A deterministic rule kernel derives the relation. Validators compare the decision, normalized discriminators, scope flags, controlling rules and independently supported citations. A well-formed leader answer is insufficient.

Two standalone consumer contracts enforce different consequences. `ReceivableConsumer` reserves capacity against an existing economic ID only after a finalized SAME obligation certificate. Its pending and unresolved holds count against capacity. `IncidentConsumer` links renamed incident records only after a finalized SAME incident certificate; recurring incidents stay separate. The consumers use separate signing accounts and preserve operation acknowledgements and applied generations.

## Package

| File | Responsibility |
| --- | --- |
| [contracts/signet.py](contracts/signet.py) | Policies, public source commitments, identity consensus, aliases, quarantine and delivery journal |
| [contracts/receivable.py](contracts/receivable.py) | Fixed-point capacity, reservations and unresolved holds |
| [contracts/incident.py](contracts/incident.py) | Incident links and separate historical record IDs |
| [scripts/envelopes.py](scripts/envelopes.py) | Canonical request and source-manifest builders |
| [scripts/signet_cli.py](scripts/signet_cli.py) | Signed operations, views and journaled receipt recovery |
| [tests/direct](tests/direct) | Deterministic state tests and explicit validator rejection probes |
| [tests/integration](tests/integration) | Real Studio consensus and delivery verification |

Every contract is independently deployable as a single Python file. The pinned runner is `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`. The runtime probe in [evidence](evidence) verifies the baseline on Studio chain 61999, including finalized messages, storage records and transaction time.

## Installation

Python 3.12 or newer is required by the GenLayer SDK. The recorded clean installation used Python 3.14.4.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/genvm-lint check contracts/signet.py
.venv/bin/genvm-lint check contracts/receivable.py
.venv/bin/genvm-lint check contracts/incident.py
.venv/bin/pytest tests/direct -v
```

On a Python installation without `ensurepip`, create the environment with `python3 -m venv --without-pip .venv` and install pip inside that environment. The recorded dependency versions are in [evidence/installed-dependencies.txt](evidence/installed-dependencies.txt).

## Builder integration

Deploy Signet with no constructor arguments. The signer becomes the configuration owner. Deploy a consumer with `(resolver, policy_id, policy_revision, schema_id)` from the consumer's own account. Configure the resolver's immutable schema and policy revision, then have the consumer owner call `approve_configuration()`. That method sends the registration from the consumer contract itself.

Register a source principal and its public HTTPS channel through an owner-signed transaction. The principal then calls `attest_source()` with the byte commitment, scope, subject ID, revision and required line-span commitments. A URL or hash alone supplies no authority. The configured principal attests provenance only within the owner's disclosed trust configuration.

Build the two manifests and request envelope with [scripts/envelopes.py](scripts/envelopes.py). Before comparison, prepare the consumer operation with the exact envelope and consequence. Call `compare_records()` to lock the request, then `evaluate()` to reserve a bounded attempt. The substantive assessment executes through a finalized self-message. Wait for `get_relation()` to report the application finality barrier, then call `publish_to()` with the prepared operation ID. The consumer acts only on an authenticated finalized source-contract message and checks current revocation at action time.

A synchronous view is useful for inspection and freshness checks. It is not a certificate of finality. Consumers must implement the authenticated callback route or an independently verified finalized receipt route.

```bash
export SIGNET_PRIVATE_KEY="$YOUR_SECURELY_LOADED_SIGNING_KEY"
.venv/bin/python -m scripts.signet_cli deploy signet --operation-id deploy-resolver
.venv/bin/python -m scripts.signet_cli compare "$RESOLVER" request.json --schema-id obligation:v1
.venv/bin/python -m scripts.signet_cli write "$RESOLVER" evaluate --args-file evaluate-args.json --operation-id evaluate-r1
.venv/bin/python -m scripts.signet_cli publish "$RESOLVER" "$CONSUMER" reserve-r1 r1
.venv/bin/python -m scripts.signet_cli reconcile "$RESOLVER" "$CONSUMER" reserve-r1
```

The CLI's operation journal records broadcasts before receipt polling. Reusing an identical operation resumes it; conflicting local reuse is rejected. Contract request IDs and delivery operation IDs independently enforce the same rule on-chain. Never place private originals or signing keys in transaction inputs.

Read [the ABI and schemas](docs/api.md), [the consumer integration guide](docs/integration.md), [the security and lifecycle specification](docs/security.md), and [the executed verification record](docs/verification.md) before rebinding another application.
