# Integrating consumers

## Receivable reservations

`ReceivableConsumer` is a reusable reservation contract, not an issuer of receivables. Its owner registers an existing economic ID and a fixed integer capacity through `register_economic_id(economic_id, capacity_minor)`. Amounts are unsigned 256-bit integers in explicitly recorded minor units. It cannot infer currency scaling from a decimal display value.

The consumer owner grants reservation permission with `set_party(account, allowed)`. A permitted party prepares a hold using:

```python
client.write_contract(
    consumer_address,
    "reserve",
    args=[operation_id, canonical(envelope), existing_economic_id, amount_minor],
)
```

The right-hand historical subject ID in the envelope must equal the existing economic ID. The consequence commitment is exactly:

```python
{
    "action": "RESERVE_EXISTING",
    "economic_id": existing_economic_id,
    "amount_minor": amount_minor,
    "reservation_owner": signing_party_address.lower(),
}
```

A pending hold immediately consumes capacity. A second reservation cannot use that pending capacity even before a positive acknowledgement. SAME becomes PERMITTED only through authenticated finalized delivery under an OBLIGATION schema with complete coverage. DISTINCT becomes REFUSED_DISTINCT. UNKNOWN becomes REFUSED_UNRESOLVED. Both retain the hold under KEEP_HOLD until its reservation owner calls `release(operation_id)`.

Only the reservation owner can release the hold, regardless of the resolver owner's or assessor's permissions. Identical repeated reserve and release calls are idempotent. A conflicting reserve under the same operation ID is rejected. Before preparing another generation for the same subject, the original operation owner must release the earlier hold.

`get_capacity(economic_id)` returns `capacity_minor`, `held_minor` and `available_minor`. `get_operation(operation_id)` returns the original bindings, consequence, owner, persisted status, current effective status, acknowledgement and last applied generation. Current effective status changes to QUARANTINED when the resolver marks the source, policy or relation inactive, or records a conflicting DISTINCT witness. A builder must check effective status at the time it uses the reservation.

The integration test's permitted action reserves 12,500 minor units against the existing economic ID after a reissued invoice is resolved as SAME. Its refused action retains a pending hold while refusing to reuse a next month's invoice as the same obligation.

## Incident directory links

`IncidentConsumer` accepts prepared operations through:

```python
client.write_contract(
    incident_consumer_address,
    "propose_link",
    args=[operation_id, canonical(envelope)],
)
```

The consequence commitment is exactly:

```python
{
    "action": "LINK_INCIDENT",
    "canonical_id": envelope["right_subject_id"],
    "record_id": envelope["subject_id"],
    "link_owner": signing_party_address.lower(),
}
```

A finalized SAME certificate under an INCIDENT schema permits the link. `resolve_record(record_id)` returns the canonical ID only while the operation's current effective status is PERMITTED. DISTINCT, UNKNOWN, quarantine and timeout return the historical record ID and a visible status. DO_NOT_LINK is the agreed unresolved consequence.

The operation owner may call `release(operation_id)` to retire a link before preparing a successor generation. The contract keeps the original operation and record IDs. Superseding an erroneous alias does not rewrite consumer history.

The integration test's permitted action links a renamed incident to its existing occurrence. Its refused action retains a recurring incident as a separate record after its date and occurrence ID conflict.

## Authenticated delivery adapter

Custom applications can implement the same public methods:

```python
@gl.public.write
def receive_certificate(self, certificate_json: str) -> None:
    ...

@gl.public.view
def get_acknowledgement(self, operation_id: str) -> str:
    ...
```

The certificate object has exactly `source_contract`, `consumer`, `operation_id` and `relation`. Authenticate the immediate transaction sender against the configured resolver, not the transaction origin. Compare the complete certificate bindings to the prepared intent. Require the finalized application barrier and the consumer's agreed schema and decision. Then inspect current resolver state for quarantine, supersession and source-revision changes.

Persist both the action and its acknowledgement atomically. The acknowledgement has `operation_id`, `payload_digest`, `status` and `generation`. Its payload digest is SHA-256 of the entire canonical certificate. Return it through:

```python
gl.get_contract_at(self.resolver).emit(on="finalized").acknowledge(
    gl.message.contract_address.as_hex,
    operation_id,
    canonical(acknowledgement),
)
```

An identical duplicate callback must return the original acknowledgement without applying the action again. Refuse conflicting reuse. Keep the highest prepared generation and the last applied generation separately. Reordered callbacks for earlier generations must not remove a newer restriction, restore an old link, or release capacity.

Use `register_consumer()` from the consumer contract itself. Its owner approves the resolver and policy, while the contract sends the registration. The adapter must explicitly define its UNKNOWN consequence; it cannot treat missing evidence as successful identity.

## Recovery and rebinding

`publish_to()` journals its broadcast by consumer and operation ID. If the process crashes after broadcast, resume the same journaled transaction hash rather than submitting another arbitrary operation. If delivery completion is uncertain, call `reconcile_delivery()`. The resolver first queries `get_acknowledgement(operation_id)` and verifies its payload digest. It retries only when the acknowledgement is absent, with a maximum of three broadcasts.

If the delivery remains unresolved, keep the prepared consumer restriction. Recovery does not assume that an unacknowledged action was never applied. For a changed source, obtain a newly attested sequential source revision and create a successor request. A finalized successor marks the predecessor SUPERSEDED while preserving its original IDs and references.

Quarantine is immediate at action time through current validity checks. New policy versions are immutable; consumers cannot be silently rebound by the resolver owner. Deploy a new consumer for another policy version. An incompatible schema or storage migration requires a new resolver deployment and explicit binding approval.

## Executable commands

The generic builder CLI signs with `SIGNET_PRIVATE_KEY` and journals operations locally:

```bash
.venv/bin/python -m scripts.signet_cli deploy receivable --args-file consumer-constructor.json --operation-id deploy-receivable
.venv/bin/python -m scripts.signet_cli write "$CONSUMER" approve_configuration --operation-id approve-receivable
.venv/bin/python -m scripts.signet_cli write "$CONSUMER" register_economic_id --args-file economic-id.json --operation-id register-economic-id
.venv/bin/python -m scripts.signet_cli write "$CONSUMER" reserve --args-file reserve-args.json --operation-id prepare-reservation
.venv/bin/python -m scripts.signet_cli view "$CONSUMER" get_operation --args-file operation-id.json
.venv/bin/python -m scripts.signet_cli write "$CONSUMER" release --args-file operation-id.json --operation-id release-reservation
```

Each argument file contains a JSON array in ABI order. `consumer-constructor.json` is `[resolver_address, "obligation", 1, "obligation:v1"]`. `economic-id.json` is `[existing_economic_id, capacity_minor]`. `reserve-args.json` is `[operation_id, canonical_envelope_string, existing_economic_id, amount_minor]`. `operation-id.json` is `[operation_id]`.

The incident equivalent uses `deploy incident` and `propose_link`, with `[operation_id, canonical_envelope_string]`. The full real network suite is executable with `python -m scripts.run_batch` after loading the three separate secure signing keys and publishing its disclosed test corpus. It does not use a mock web service, mock model or leader-only network mode.
