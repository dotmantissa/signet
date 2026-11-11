# Contract ABI and canonical schemas

All methods are public GenLayer Python methods. Address arguments use hexadecimal address strings. Structured transaction inputs use UTF-8 JSON strings with exact key sets. `canonical()` in `scripts/envelopes.py` sorts keys, removes insignificant whitespace and preserves UTF-8. SHA-256 digests hash those canonical UTF-8 bytes. Write calls return transaction receipts through the SDK; inspect their execution result as well as lifecycle status.

## Constructors

```python
resolver = client.deploy_contract(code=resolver_code, args=[])
receivable = receivable_client.deploy_contract(
    code=receivable_code,
    args=[resolver_address, "obligation", 1, "obligation:v1"],
)
incident = incident_client.deploy_contract(
    code=incident_code,
    args=[resolver_address, "incident", 1, "incident:v1"],
)
```

Signet takes no arguments. The deployment sender becomes its owner and initial assessor. Each consumer takes the resolver address, policy ID, unsigned 64-bit policy revision and schema ID. Its deployment sender becomes its owner and initial approved party. Consumers are immutable bindings to one resolver and policy version.

## Resolver writes

| Method | Arguments and example | Permission and result |
| --- | --- | --- |
| `set_assessor` | `(account, allowed)`, `("0x...", True)` | Owner; grants assessment only |
| `register_identity_schema` | `(schema_id, mandatory_discriminators)`, `("obligation:v1", ["payer_id", "payee_id", "consideration", "period", "amount_minor", "currency"])` | Owner; immutable supported schema |
| `register_policy` | `(policy_id, revision, schema_id, scope)`, `("obligation", 1, "obligation:v1", "obligation")` | Owner; immutable version |
| `register_authority` | `(authority_id, principal, url_prefix, public_evidence_url)`, `("issuer", "0x...", "https://records.publisher.org/public/", "https://records.publisher.org/authority")` | Owner; explicit provenance configuration |
| `attest_source` | `(source_json)`, `canonical(source)` below | Only configured source principal |
| `register_consumer` | `(consumer, configuration_json)` below | Must arrive from the consumer contract address |
| `compare_records` | `(request_id, schema_id, left_manifest, right_manifest, envelope_json)`, `("r1", "obligation:v1", canonical(left), canonical(right), canonical(envelope))` | Authorized assessor and bound request owner; locks request without evaluating it |
| `evaluate` | `(request_id)`, `("r1",)` | Request owner; reserves and emits an assessment attempt, or exposes exhaustion |
| `assess_attempt` | `(request_id, attempt)`, `("r1", 1)` | Authenticated finalized self-message only; independent semantic consensus |
| `confirm_relation` | `(request_id)`, `("r1",)` | Authenticated finalized self-message only; records the application finality barrier |
| `register_alias` | `(subject_id, relation_id)`, `("invoice-reissued", "r1")` | Request owner or covered principal; requires finalized active SAME witnesses; bounded unresolved status otherwise |
| `quarantine` | `(category, item_id)`, `("source", "invoice-1:1")` | Owner; category is relation, source, policy, authority or consumer |
| `publish_to` | `(request_id, consumer, operation_id)`, `("r1", "0x...", "reserve-r1")` | Request owner or bound consumer; finalized authenticated emission only |
| `acknowledge` | `(consumer, operation_id, acknowledgement_json)` | Consumer address only; persists its bound acknowledgement |
| `reconcile_delivery` | `(consumer, operation_id)`, `("0x...", "reserve-r1")` | Request owner or consumer; reads acknowledgement before bounded retransmission |

Registering a byte-for-byte identical schema, policy, authority, source revision, consumer configuration or request is idempotent. Conflicting ID reuse is an expected error. Source heads advance sequentially from revision 1. A subject's first attesting principal owns its provenance binding. The owner cannot subsequently overwrite that binding.

Schema field sets are fixed in this deployment. Names, arbitrary new discriminators, private personal identity and biometrics are not supported. Organization schemas require official ID and jurisdiction; incident schemas require event date, location ID, event kind and occurrence ID. `schema_id` is an immutable identifier, not a prompt.

## Resolver views

| Method | Example arguments | Return |
| --- | --- | --- |
| `get_relation` | `("r1",)` | Bound envelope, lifecycle, canonical decision vector, current validity, attempts, fingerprint and superseding ID |
| `get_alias` | `("invoice-reissued",)` | Historical ID, effective canonical ID, bounded cluster and current validity |
| `get_cluster` | `(cluster_id,)` | Historical members, controlling relation, policy key, active flag and superseding ID |
| `get_configuration` | `("policy", "obligation:1")` | Immutable payload and active flag; category is schema, policy or authority |
| `get_delivery` | `("0x...", "reserve-r1")` | Request ID, operation ID, status, attempts, payload digest and acknowledgement JSON |
| `history_page` | `(0, 100)` | Up to 100 canonical journal strings |
| `revision_relations` | `("source", "invoice-1:1", 0, 100)` | Bounded page of related request IDs; category is source, subject or policy |
| `limits` | `()` | Published admission and integer limits |

Unknown IDs, invalid pagination and unauthorized writes raise expected deterministic errors with `[EXPECTED]`. Model shape, field, flag or witness failures raise `[LLM_ERROR]` and fail validator agreement. VM errors always fail the substantive validator. External outages are canonical unavailable results, never affirmative facts.

## Source schema

Every committed document appears in exactly one of the two manifests. Documents are independently retrieved in full; there is no caller-supplied document text or truncation field.

```python
from scripts.envelopes import source_manifest, canonical

source = source_manifest(
    source_id="invoice-1",
    subject_id="invoice-original",
    authority_id="issuer",
    url="https://records.publisher.org/public/invoice-1.txt",
    raw=downloaded_public_bytes,
    scope="obligation",
    revision=1,
)
issuer_client.write_contract(resolver_address, "attest_source", args=[canonical(source)])
```

```json
{
  "source_id": "invoice-1",
  "authority_id": "issuer",
  "channel": "HTTPS_UTF8",
  "url": "https://records.publisher.org/public/invoice-1.txt",
  "raw_hash": "64 lowercase hexadecimal SHA-256 characters",
  "revision": 1,
  "scope": "obligation",
  "subject_id": "invoice-original",
  "byte_length": 347,
  "required_spans": [
    {"start": 0, "end": 75, "span_hash": "SHA-256 of those exact raw bytes"}
  ]
}
```

The example digest placeholders illustrate types. Executable builders compute actual commitments; complete real test requests appear under `evidence/studio-final/`. Byte offsets are half-open `[start,end)`. A required span must be a complete nonempty line in the deterministic raw UTF-8 mapping, including its existing newline bytes. The helper commits every nonempty line. Witness IDs are `raw_hash:start:end`. Identical line text in another document does not authorize changing the raw source hash.

```json
{
  "subject_id": "invoice-original",
  "sources": ["one or two full source objects, not IDs alone"]
}
```

The executable manifest uses source objects. It requires at least one source per side and at most four across both sides, with no duplicate source ID.

## Consumer configuration

```json
{
  "policy_id": "obligation",
  "policy_revision": 1,
  "schema_id": "obligation:v1",
  "unresolved_consequence": "KEEP_HOLD"
}
```

The incident policy uses `DO_NOT_LINK`. `approve_configuration()` constructs and sends this object from the consumer address. Custom consumer contracts must approve their own configuration through the same authenticated route. Assessment permission cannot substitute for consumer approval.

## Request envelope

```python
from scripts.envelopes import request_envelope, canonical

consequence = {
    "action": "RESERVE_EXISTING",
    "economic_id": "existing-economic-id",
    "amount_minor": 12500,
    "reservation_owner": reservation_owner_address.lower(),
}
envelope = request_envelope(
    request_id="r1",
    owner=assessor_address,
    parties=[issuer_address],
    policy_id="obligation",
    policy_revision=1,
    left=left_manifest,
    right=right_manifest,
    consumer=consumer_address,
    consequence=consequence,
    generation=1,
    deadline=deadline_unix_seconds,
)
```

The exact fields are:

```json
{
  "request_id": "r1",
  "owner": "0x...",
  "parties": ["0x..."],
  "policy_id": "obligation",
  "policy_revision": 1,
  "subject_id": "invoice-reissued",
  "right_subject_id": "existing-economic-id",
  "subject_digest": "SHA-256 of canonical [left subject ID, right subject ID]",
  "source_manifest_digest": "SHA-256 of canonical [left manifest, right manifest]",
  "consumer": "0x...",
  "consequence_digest": "SHA-256 of canonical consequence object",
  "generation": 1,
  "deadline": 1795000000,
  "supersedes": ""
}
```

`parties` is the sorted unique list of configured principals covering every source, using lowercase addresses. `owner` is the assessment sender. The subject IDs must differ even when the records eventually denote one subject. The deadline uses Unix seconds checked against GenVM's transaction-provided datetime. No local wall clock enters contract logic.

A successor uses a new request ID, a greater generation and the predecessor's ID in `supersedes`. The request owner, consumer, historical subject pair and policy ID must match the predecessor. Schema kind, mandatory discriminator set and scope must remain compatible. Source revisions and consequence are separately committed. An incompatible rebinding uses another deployment.

## Canonical result

```json
{
  "bindings": "the unchanged complete request envelope",
  "status": "FINALIZED",
  "decision_vector": {
    "availability": "AVAILABLE",
    "relation": "SAME",
    "reason": "ALL_DISCRIMINATORS_MATCH",
    "discriminators": ["left normalized mandatory field map", "right normalized mandatory field map"],
    "scope_flags": ["left controlling flag map", "right controlling flag map"],
    "scope": "obligation",
    "controlling_rule_ids": ["R1_COMPLETE", "R2_DISCRIMINATORS", "R3_SCOPE", "R6_NO_NAME_ONLY"],
    "witnesses": ["left field-to-span-ID map", "right field-to-span-ID map"],
    "adequate_witness_sets": ["left supported span sets", "right supported span sets"],
    "coverage": true,
    "unresolved": [],
    "different_fields": []
  },
  "active": true,
  "superseded_by": "",
  "attempts": 1,
  "fingerprint": "policy, scope and discriminator fingerprint"
}
```

The displayed type descriptions stand for actual objects, which are present in recorded integration results. Witness map keys are `fields:<mandatory field>` and `flags:<flag name>`. An empty witness string and empty adequate set mean no supported witness. Unavailable terminal results still contain the same canonical vector fields, with `coverage=false` and explicit unresolved reasons. Empty discriminator values or default flags in an uncovered result are not absence certificates. Before evaluation, the view explicitly returns UNKNOWN with `NOT_EVALUATED`; there is no substantive certificate yet.

Enums and labels:

| Category | Values |
| --- | --- |
| Relation | `SAME`, `DISTINCT`, `UNKNOWN` |
| Lifecycle | `LOCKED`, `EVALUATING`, `UNRESOLVED`, `ASSESSED`, `FINALIZED`, `SUPERSEDED`, `QUARANTINED` |
| Availability | `AVAILABLE`, `UNAVAILABLE`, `CHANGED`, `OVERSIZED` |
| Scope flags | `related_only`, `identifier_reissued`, `recurring`, `scope_ambiguous`, `controlling_exception` |
| Rule IDs | `R1_COMPLETE`, `R2_DISCRIMINATORS`, `R3_SCOPE`, `R4_RELATED`, `R5_EXCEPTION`, `R6_NO_NAME_ONLY`, `R7_REVISION` |
| Available result reasons | `ALL_DISCRIMINATORS_MATCH`, `DISCRIMINATOR_CONFLICT`, `CONTROLLING_EXCEPTION`, `RELATED_NOT_IDENTICAL`, `AMBIGUOUS_SCOPE`, `MISSING_DISCRIMINATORS` |
| Unavailable reasons | `SOURCE_UNAVAILABLE`, `SOURCE_CHANGED`, `INVALID_UTF8`, `SPAN_COMMITMENT_MISMATCH`, `COMPLETE_CONTEXT_OVERSIZED`, `SOURCE_SPAN_LIMIT`, `PROMPT_TOKEN_CEILING`, `RETRY_EXHAUSTED`, `DEADLINE_EXPIRED` |
| Alias unresolved returns | `UNRESOLVED_CLUSTER_BOUND`, `UNRESOLVED_DISTINCT_BOUND`, `UNRESOLVED_DISTINCT_EDGE`, `UNRESOLVED_CROSS_WITNESS`, `UNRESOLVED_SCOPE_OR_REVISION` |
| Delivery | `QUEUED`, `ACKNOWLEDGED`, `UNRESOLVED_DELIVERY` |
| Consumer operation | `PENDING`, `PERMITTED`, `REFUSED_DISTINCT`, `REFUSED_UNRESOLVED`, `QUARANTINED`, `TIMEOUT`, `RELEASED` |
| Callback acknowledgement | The operation labels above, plus `STALE` |

A terminal finalized UNKNOWN authorizes only the consumer's agreed unresolved consequence. The exact admission and integer bounds are published by `limits()` and in [security.md](security.md).
