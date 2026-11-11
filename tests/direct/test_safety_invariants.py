"""Application invariants across accepted output, revocation and recovery paths."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import hashlib
import pytest
from scripts.envelopes import canonical, digest, source_manifest


@pytest.mark.parametrize('fixture_name', ['harness', 'incident'])
@pytest.mark.parametrize('mutation', ['integer_coverage', 'float_coverage', 'false_flag_integer', 'field_integer', 'rules_integer', 'extra_witness_side', 'missing_witness_side', 'extra_witness_field', 'extra_adequate_field'])
def test_validator_rejects_wrong_nested_types_and_shapes(request, fixture_name, mutation):
    h = request.getfixturevalue(fixture_name)
    h.make(); h.evaluate()
    candidate = deepcopy(h.vm._captured_validators[-1][0])
    if mutation == 'integer_coverage': candidate['coverage'] = 1
    elif mutation == 'float_coverage': candidate['coverage'] = 1.0
    elif mutation == 'false_flag_integer': candidate['scope_flags'][0]['recurring'] = 0
    elif mutation == 'field_integer': candidate['discriminators'][0][next(iter(candidate['discriminators'][0]))] = 1
    elif mutation == 'rules_integer': candidate['controlling_rule_ids'][0] = 1
    elif mutation == 'extra_witness_side': candidate['witnesses'].append(candidate['witnesses'][0])
    elif mutation == 'missing_witness_side': candidate['adequate_witness_sets'].pop()
    elif mutation == 'extra_witness_field': candidate['witnesses'][0]['injected'] = ''
    elif mutation == 'extra_adequate_field': candidate['adequate_witness_sets'][0]['injected'] = []
    assert h.vm.run_validator(leader_result=candidate) is False


@pytest.mark.parametrize('fixture_name', ['harness', 'incident'])
@pytest.mark.parametrize('subset', ['first', 'last', 'all'])
def test_every_accepted_equivalent_witness_choice_preserves_consumer_action(request, fixture_name, subset):
    h = request.getfixturevalue(fixture_name)
    field, value = ('payer_id', 'reg:payer') if fixture_name == 'harness' else ('occurrence_id', 'outage:42')
    h.make(extra_lines=[field + ': ' + value])
    answer = deepcopy(h.answer)
    for side, manifest in enumerate(h.manifests):
        source = manifest['sources'][0]
        # The duplicate final line independently supports the same identifying fact.
        end = source['byte_length']; start = end - len((field + ': ' + value + '\n').encode())
        duplicate = str(side) + ':' + source['source_id'] + ':' + source['raw_hash'] + ':' + str(start) + ':' + str(end)
        first_span = next(span for span in source['required_spans'] if span['end'] <= start and span['span_hash'] == hashlib.sha256((field + ': ' + value + '\n').encode()).hexdigest())
        initial = str(side) + ':' + source['source_id'] + ':' + source['raw_hash'] + ':' + str(first_span['start']) + ':' + str(first_span['end'])
        answer['sides'][side]['fields'][field]['spans'] = sorted([initial, duplicate])
    h.vm._llm_mocks.clear(); h.vm.mock_llm('SIGNET_IDENTITY_EXTRACTION_V1', json.dumps(answer))
    h.evaluate()
    candidate = deepcopy(h.vm._captured_validators[-1][0])
    for side in range(2):
        adequate = candidate['adequate_witness_sets'][side]['fields:' + field]
        assert len(adequate) == 2
        choice = adequate if subset == 'all' else [adequate[0 if subset == 'first' else -1]]
        candidate['adequate_witness_sets'][side]['fields:' + field] = choice
        candidate['witnesses'][side]['fields:' + field] = choice[0]
    assert h.vm.run_validator(leader_result=candidate) is True
    # Model the approved variant returned by consensus; application action stays identical.
    with h.world.context(h.signet): h.signet.contract.relations['r1'].result = canonical(candidate)
    assert h.deliver()['effective_status'] == 'PERMITTED'
    if fixture_name == 'harness': assert h.consumer.get_capacity('right')['held_minor'] == 12500
    else: assert h.consumer.resolve_record('left')['canonical_id'] == 'right'


@pytest.mark.parametrize('fixture_name', ['harness', 'incident'])
def test_expired_identical_operation_retains_idempotency(request, fixture_name):
    h = request.getfixturevalue(fixture_name)
    e, _ = h.make(); h.evaluate(); h.deliver()
    before = h.consumer.get_operation('r1')
    h.vm.warp('2034-01-01T00:00:00Z')
    if fixture_name == 'harness': h.consumer.reserve('r1', canonical(e), 'right', 12500)
    else: h.consumer.propose_link('r1', canonical(e))
    assert h.consumer.get_operation('r1') == before


@pytest.mark.parametrize('fixture_name', ['harness', 'incident'])
def test_principal_recovers_revoked_operator_subject_without_double_release(request, fixture_name):
    h = request.getfixturevalue(fixture_name)
    h.make(prepare=False)
    h.consumer.set_party(str(h.bob), True)
    h.signet.set_subject_operator('left', str(h.bob), True)
    e = deepcopy(h.envelope)
    consequence = {'action': 'RESERVE_EXISTING', 'economic_id': 'right', 'amount_minor': 12500, 'reservation_owner': str(h.bob).lower()} if fixture_name == 'harness' else {'action': 'LINK_INCIDENT', 'canonical_id': 'right', 'record_id': 'left', 'link_owner': str(h.bob).lower()}
    e['consequence_digest'] = digest(consequence)
    with h.vm.prank(h.bob):
        if fixture_name == 'harness': h.consumer.reserve('delegate', canonical(e), 'right', 12500)
        else: h.consumer.propose_link('delegate', canonical(e))
    with h.vm.expect_revert('revoke previous operator'): h.consumer.recover_subject('left')
    h.signet.set_subject_operator('left', str(h.bob), False)
    with h.vm.prank(h.bob), h.vm.expect_revert('only subject principal'): h.consumer.recover_subject('left')
    h.consumer.recover_subject('left'); h.consumer.recover_subject('left')
    assert h.consumer.get_operation('delegate')['status'] == 'RELEASED'
    e = deepcopy(h.envelope); e['generation'] = 2
    if fixture_name == 'harness':
        assert h.consumer.get_capacity('right')['held_minor'] == 0
        h.consumer.reserve('recovered', canonical(e), 'right', 12500)
        assert h.consumer.get_capacity('right')['held_minor'] == 12500
    else: h.consumer.propose_link('recovered', canonical(e))


@pytest.mark.parametrize('category', ['relation', 'source', 'policy', 'authority', 'consumer', 'manifest'])
def test_every_correction_revocation_restores_negative_dependency(harness, category):
    h = harness
    h.make('negative', prepare=False, changes={'period': '2026-11'}); h.evaluate('negative')
    h.vm.clear_mocks(); h.make('correction', prepare=False, supersedes='negative'); h.evaluate('correction')
    assert h.signet._negative_active('negative') is False
    item = {'relation': 'correction', 'source': h.manifests[0]['sources'][0]['source_id'] + ':' + str(h.manifests[0]['sources'][0]['revision']), 'policy': h.policy + ':1', 'authority': 'issuer', 'consumer': str(h.consumer_address), 'manifest': digest(['obligation', h.manifests[0]])}[category]
    h.signet.quarantine(category, item)
    assert h.signet._negative_active('negative') is True
    assert h.signet._edge_veto(digest(['', ['left', 'right']])) is True


def test_correction_dependency_survives_same_successor_and_restores_on_unknown(harness):
    h = harness
    h.make('negative', prepare=False, changes={'period': '2026-11'}); h.evaluate('negative')
    h.vm.clear_mocks(); h.make('correction', prepare=False, supersedes='negative'); h.evaluate('correction')
    h.vm.clear_mocks(); h.make('current', prepare=False, supersedes='correction'); h.evaluate('current')
    assert h.signet._negative_active('negative') is False
    h.vm.clear_mocks(); h.make('unknown', prepare=False, supersedes='current', missing='period'); h.evaluate('unknown')
    assert h.signet._negative_active('negative') is True


def test_confirmation_recovery_is_bounded_and_emitted_only_after_finality(harness):
    h = harness
    h.make(); h.evaluate(finalize=False)
    for attempt in range(1, 4):
        assert h.signet.get_relation('r1')['confirmation_attempts'] == attempt
        confirms = [m for m in h.world.messages if m['calldata']['method'] == 'confirm_relation']
        assert len(confirms) == 1 and confirms[0]['on'] == 'finalized'
        h.world.messages.clear()
        now = int(h.signet.confirmation_times['r1']) + 61
        h.vm.warp(datetime.fromtimestamp(now, timezone.utc).isoformat()); h.signet.evaluate('r1')
    assert h.signet.get_relation('r1')['confirmation_attempts'] == 3
    assert not h.world.messages


def test_full_history_does_not_block_finalization_delivery_or_quarantine(harness, monkeypatch):
    h = harness
    monkeypatch.setitem(h.signet.contract._journal.__globals__, 'MAX_HISTORY', 20)
    h.make()
    while h.signet.limits()['dropped_history_events'] == 0: h.signet.set_assessor(str(h.bob), False)
    assert len(h.signet.history_page(0,100)) == 20
    h.evaluate(); assert h.deliver()['effective_status'] == 'PERMITTED'
    h.signet.quarantine('relation', 'r1')
    assert h.consumer.get_operation('r1')['effective_status'] == 'QUARANTINED'
    h.consumer.release('r1'); assert h.consumer.get_capacity('right')['held_minor'] == 0


def test_source_owner_cannot_change_subject_or_scope_and_can_withdraw_explicitly(harness):
    h = harness; h.make()
    for field, value in [('subject_id', 'other'), ('scope', 'other')]:
        source = deepcopy(h.manifests[0]['sources'][0]); source['revision'] += 1; source[field] = value
        with h.vm.expect_revert('immutable source principal subject and scope'): h.signet.attest_source(canonical(source))
    source_id = h.manifests[0]['sources'][0]['source_id']
    with h.vm.prank(h.bob), h.vm.expect_revert('only bound source principal'): h.signet.withdraw_source(source_id, 'unauthorized')
    h.signet.withdraw_source(source_id, 'Obsolete record explicitly retired by its principal')
    assert h.signet.get_record_manifest('left', 'obligation')['manifest']['sources'] == []
