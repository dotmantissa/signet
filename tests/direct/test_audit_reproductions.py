"""Regressions for typed consensus, evidence ownership, aliases and recovery."""
from copy import deepcopy
import json

import pytest

from scripts.envelopes import canonical, digest, source_manifest


@pytest.mark.parametrize('fixture_name', ['harness', 'incident'])
def test_consensus_rejects_integer_coverage(request, fixture_name):
    h = request.getfixturevalue(fixture_name)
    h.make()
    h.evaluate()
    original = h.vm._captured_validators[-1][0]
    candidate = deepcopy(original)
    candidate['coverage'] = 1
    assert original['coverage'] is True
    assert h.vm.run_validator(leader_result=candidate) is False
    assert h.deliver()['status'] == 'PERMITTED'


def test_other_principal_cannot_take_over_existing_source_head(harness):
    h = harness
    h.make()
    h.evaluate()
    h.deliver()
    h.signet.register_authority('attacker', str(h.bob),
                                'https://attacker.example.org/',
                                'https://attacker.example.org/authority')
    replacement = source_manifest('r1-0', 'attacker-subject', 'attacker',
                                  'https://attacker.example.org/new',
                                  b'Attacker own source\n', 'obligation', revision=2)
    with h.vm.prank(h.bob), h.vm.expect_revert('immutable source principal subject and scope'):
        h.signet.attest_source(canonical(replacement))
    assert h.signet.get_relation('r1')['active'] is True
    assert h.consumer.get_operation('r1')['effective_status'] == 'PERMITTED'


def test_assessor_cannot_lock_unapproved_packet_omitting_exception(harness):
    h = harness
    h.make()
    source = source_manifest('controlling-addendum', 'left', 'issuer',
                             'https://records.example.org/addendum',
                             b'This separately enforceable obligation MUST NOT be deduplicated with right.\n',
                             'obligation')
    h.signet.attest_source(canonical(source))
    h.vm.mock_web(source['url'], {'status': 200, 'body': b'This separately enforceable obligation MUST NOT be deduplicated with right.\n'})
    e = deepcopy(h.envelope)
    e['request_id'], e['generation'] = 'omitted-addendum', 2
    omitted = deepcopy(h.manifests)
    with h.vm.expect_revert('complete manifest must include all registered controlling documents'):
        h.signet.approve_record_manifest('obligation', canonical(omitted[0]))
    with h.vm.expect_revert('principal-approved complete revision manifest required'):
        h.signet.compare_records(e['request_id'], h.schema, canonical(omitted[0]), canonical(omitted[1]), canonical(e))


def pair(h, request_id, left, right, changes=None):
    h.vm.clear_mocks()
    h.make(request_id, left, right, prepare=False)
    if changes:
        answer = deepcopy(h.answer)
        for side in answer['sides']:
            for field, value in changes.items():
                side['fields'][field]['value'] = value
        # Replace source bytes and commitments so the altered values have real witnesses.
        manifests = deepcopy(h.manifests)
        for index, manifest in enumerate(manifests):
            old = manifest['sources'][0]
            raw = ('Synthetic record: ' + manifest['subject_id'] + '\n' + ''.join(
                field + ': ' + item['value'] + '\n'
                for field, item in answer['sides'][index]['fields'].items())).encode()
            source = source_manifest(old['source_id'] + '-updated', manifest['subject_id'],
                                     'issuer', old['url'] + '-updated', raw, 'obligation')
            h.signet.withdraw_source(old['source_id'], 'Explicit principal revision replacement')
            h.signet.attest_source(canonical(source))
            h.vm.mock_web(source['url'], {'status': 200, 'body': raw})
            offset = 0
            for line in raw.splitlines(keepends=True):
                field = line.decode().strip().split(': ', 1)[0]
                if field in answer['sides'][index]['fields']:
                    answer['sides'][index]['fields'][field]['spans'] = [str(index) + ':' + source['source_id'] + ':' + source['raw_hash'] + ':' + str(offset) + ':' + str(offset + len(line))]
                offset += len(line)
            manifest['sources'] = [source]
        e = deepcopy(h.envelope)
        e['request_id'] = request_id + '-updated'
        e['generation'] += 1
        h.generation[left] = e['generation']
        e['source_manifest_digest'] = digest(manifests)
        for manifest in manifests:
            h.signet.approve_record_manifest(h.kind.lower(), canonical(manifest))
        h.signet.compare_records(e['request_id'], h.schema, canonical(manifests[0]), canonical(manifests[1]), canonical(e))
        h.vm._llm_mocks.clear()
        h.vm.mock_llm('SIGNET_IDENTITY_EXTRACTION_V1', json.dumps(answer))
        request_id = e['request_id']
    return h.evaluate(request_id)


def test_existing_alias_rechecks_bound_witness_and_fingerprint(harness):
    h = harness
    pair(h, 'ab', 'a', 'b')
    h.signet.register_alias('a', 'ab')
    pair(h, 'bc', 'b', 'c')
    pair(h, 'ac', 'a', 'c')
    cid = h.signet.register_alias('a', 'ac')
    before = h.signet.get_relation('ab')['fingerprint']
    updated = pair(h, 'new-ab', 'a', 'b', {'period': '2026-12'})
    assert updated['fingerprint'] != before
    assert h.signet.get_relation('bc')['active'] is False
    alias = h.signet.get_alias('c')
    assert alias['active'] is False
    assert alias['canonical_id'] == 'c'
    assert h.signet.get_cluster(cid)['active'] is False
    assert alias['cluster_id'] == cid
    assert alias['members'] == ['a', 'b', 'c']


def test_quarantined_correction_restores_distinct_veto(harness):
    h = harness
    h.make('distinct', prepare=False, changes={'period': '2026-11'})
    h.evaluate('distinct')
    h.vm.clear_mocks()
    h.make('correction', prepare=False, supersedes='distinct')
    h.evaluate('correction')
    h.signet.quarantine('relation', 'correction')
    h.vm.clear_mocks()
    h.make('unbound-same', prepare=False)
    h.evaluate('unbound-same')
    result = h.signet.register_alias('left', 'unbound-same')
    assert result == 'UNRESOLVED_DISTINCT_EDGE'
    assert h.signet.get_relation('unbound-same')['active'] is False


def test_older_sibling_cannot_overwrite_newer_successor(harness):
    h = harness
    h.make('base', prepare=False)
    h.evaluate('base')
    h.vm.clear_mocks()
    h.make('older', prepare=False, supersedes='base')
    h.evaluate('older', finalize=False)
    h.vm.clear_mocks()
    h.make('newer', prepare=False, supersedes='base')
    h.evaluate('newer')
    assert h.signet.get_relation('base')['superseded_by'] == 'newer'
    with h.vm.prank(h.resolver_address):
        h.signet.confirm_relation('older')
    assert h.signet.get_relation('base')['superseded_by'] == 'newer'
    assert h.signet.get_relation('older')['status'] == 'SUPERSEDED'
    assert h.signet.get_relation('older')['active'] is False
    assert h.signet.get_relation('newer')['active'] is True


def test_finality_message_loss_has_bounded_public_reschedule(harness):
    h = harness
    h.make()
    h.evaluate(finalize=False)
    h.world.messages = [m for m in h.world.messages if m['calldata']['method'] != 'confirm_relation']
    h.signet.evaluate('r1')
    assert not h.world.run_next('confirm_relation')
    from datetime import datetime, timezone
    start = h.signet.confirmation_times['r1']
    h.vm.warp(datetime.fromtimestamp(int(start) + 61, timezone.utc).isoformat())
    h.signet.evaluate('r1')
    assert h.world.run_next('confirm_relation')
    assert h.signet.get_relation('r1')['status'] == 'FINALIZED'
    assert h.signet.get_relation('r1')['confirmation_attempts'] == 2


def test_identical_source_bytes_keep_side_bound_witnesses(harness):
    h = harness
    e, original = h.make(prepare=False)
    raw = ('Shared identical public record\n' + ''.join(
        field + ': ' + item['value'] + '\n'
        for field, item in h.answer['sides'][0]['fields'].items())).encode()
    answer = deepcopy(h.answer)
    manifests = deepcopy(original)
    for index, manifest in enumerate(manifests):
        source = source_manifest('shared-' + str(index), manifest['subject_id'], 'issuer',
                                 'https://records.example.org/shared-' + str(index), raw, 'obligation')
        h.signet.withdraw_source(manifest['sources'][0]['source_id'], 'Replace with shared document')
        h.signet.attest_source(canonical(source))
        h.vm.mock_web(source['url'], {'status': 200, 'body': raw})
        offset = 0
        for line in raw.splitlines(keepends=True):
            field = line.decode().strip().split(': ', 1)[0]
            if field in answer['sides'][index]['fields']:
                answer['sides'][index]['fields'][field]['spans'] = [str(index) + ':' + source['source_id'] + ':' + source['raw_hash'] + ':' + str(offset) + ':' + str(offset + len(line))]
            offset += len(line)
        manifest['sources'] = [source]
    e = deepcopy(e)
    e['request_id'], e['generation'] = 'identical', 2
    e['source_manifest_digest'] = digest(manifests)
    for manifest in manifests:
        h.signet.approve_record_manifest(h.kind.lower(), canonical(manifest))
    h.signet.compare_records('identical', h.schema, canonical(manifests[0]), canonical(manifests[1]), canonical(e))
    h.vm._llm_mocks.clear()
    h.vm.mock_llm('SIGNET_IDENTITY_EXTRACTION_V1', json.dumps(answer))
    assert h.evaluate('identical')['decision_vector']['relation'] == 'SAME'
    assert h.vm.run_validator() is True


def test_identical_operation_replay_after_deadline_is_idempotent(harness):
    h = harness
    e, _ = h.make()
    h.vm.warp('2034-01-01T00:00:00Z')
    h.consumer.reserve('r1', canonical(e), 'right', 12500)
    assert h.consumer.get_capacity('right')['held_minor'] == 12500


def test_approved_party_cannot_squat_another_principals_subject(harness):
    h = harness
    h.make(prepare=False)
    e = deepcopy(h.envelope)
    h.consumer.set_party(str(h.bob), True)
    e['consequence_digest'] = digest({'action': 'RESERVE_EXISTING', 'economic_id': 'right',
                                     'amount_minor': 12500, 'reservation_owner': str(h.bob).lower()})
    with h.vm.prank(h.bob), h.vm.expect_revert('subject authorization required'):
        h.consumer.reserve('squat', canonical(e), 'right', 12500)
    legitimate = deepcopy(h.envelope)
    legitimate['generation'] = 2
    h.consumer.reserve('legitimate', canonical(legitimate), 'right', 12500)
    assert h.consumer.get_capacity('right')['held_minor'] == 12500


def test_unapproved_eoa_cannot_register_as_consumer(harness):
    h = harness
    with h.vm.prank(h.bob), h.vm.expect_revert('consumer admission required'):
        h.signet.register_consumer(str(h.bob), canonical({
            'policy_id': h.policy, 'policy_revision': 1, 'schema_id': h.schema,
            'unresolved_consequence': 'KEEP_HOLD'}))
    with h.world.context(h.signet):
        assert h.bob not in h.signet.contract.consumers


def test_identifier_normalization_preserves_case_sensitive_distinctions(harness):
    h = harness
    h.make(changes={'payer_id': 'REG:PAYER'})
    result = h.evaluate()
    assert h.answer['sides'][0]['fields']['payer_id']['value'] != h.answer['sides'][1]['fields']['payer_id']['value']
    assert result['decision_vector']['relation'] == 'DISTINCT'
    assert h.vm.run_validator() is True
