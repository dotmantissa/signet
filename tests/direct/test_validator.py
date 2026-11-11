"""Adversarial probes explicitly invoke the captured validator, not just leader execution."""
from copy import deepcopy
import json
import pytest


def test_valid_json_wrong_substantive_result(harness):
    h = harness
    h.make(changes={'period':'2026-11'})
    h.evaluate()
    candidate = deepcopy(h.vm._captured_validators[-1][0])
    candidate['relation'] = 'SAME'
    assert h.vm.run_validator(leader_result=candidate) is False


def test_omitted_controlling_exception(harness):
    h = harness
    h.make(flags={'controlling_exception':True})
    h.evaluate()
    candidate = deepcopy(h.vm._captured_validators[-1][0])
    candidate['scope_flags'][1]['controlling_exception'] = False
    candidate['relation'] = 'SAME'
    candidate['controlling_rule_ids'].remove('R5_EXCEPTION')
    assert h.vm.run_validator(leader_result=candidate) is False


def test_forged_span_in_valid_json(harness):
    h = harness
    h.make()
    h.evaluate()
    candidate = deepcopy(h.vm._captured_validators[-1][0])
    candidate['witnesses'][0]['fields:payer_id'] = '0'*64 + ':0:12'
    candidate['adequate_witness_sets'][0]['fields:payer_id'] = [candidate['witnesses'][0]['fields:payer_id']]
    assert h.vm.run_validator(leader_result=candidate) is False


def test_changed_source_rejects_leader_affirmative(harness):
    h = harness
    h.make()
    h.evaluate()
    h.vm.clear_mocks()
    for m in h.manifests:
        for s in m['sources']:
            h.vm.mock_web(s['url'], {'status':200, 'body':b'changed bytes'})
    assert h.vm.run_validator() is False


def test_independent_extraction_does_not_trust_leader(harness):
    h = harness
    h.make()
    h.evaluate()
    candidate = deepcopy(h.vm._captured_validators[-1][0])
    candidate['discriminators'][1]['payer_id'] = 'forged'
    assert h.vm.run_validator(leader_result=candidate) is False


@pytest.mark.parametrize('malformation', ['label','missing','forged','wrong_side','output_limit','integer_limit','null','name_only'])
def test_malformed_model_output_fails(harness, malformation):
    h = harness
    h.make()
    answer = deepcopy(h.answer)
    if malformation == 'label':
        answer['sides'][0]['flags']['recurring']['value'] = 'false'
    elif malformation == 'missing':
        del answer['sides'][0]['flags']['controlling_exception']
    elif malformation == 'forged':
        answer['sides'][0]['fields']['payer_id']['spans'] = ['forged']
    elif malformation == 'wrong_side':
        answer['sides'][0]['fields']['payer_id']['spans'] = answer['sides'][1]['fields']['payer_id']['spans']
    elif malformation == 'output_limit':
        answer['extra'] = 'x' * 17000
    elif malformation == 'integer_limit':
        answer['sides'][0]['fields']['amount_minor']['value'] = str(2**256)
    elif malformation == 'null':
        answer = None
    elif malformation == 'name_only':
        answer['sides'][0]['fields'] = {'name':{'value':'Acme','spans':[]}}
    h.vm._llm_mocks.clear()
    h.vm.mock_llm('SIGNET_IDENTITY_EXTRACTION_V1', json.dumps(answer))
    with h.vm.expect_revert():
        h.evaluate()
    assert h.signet.get_relation('r1')['attempts'] == 1
    assert h.signet.get_relation('r1')['status'] == 'EVALUATING'


def test_llm_user_error_is_not_consensus(harness):
    harness.make()
    harness.evaluate()
    assert harness.vm.run_validator(leader_error=Exception('[LLM_ERROR] malformed')) is False
    assert harness.vm.run_validator(leader_error=Exception('[TRANSIENT] outage')) is False


def test_vm_error_explicitly_rejected(harness):
    from genlayer import gl
    harness.make()
    harness.evaluate()
    _, derive, validator = harness.vm._captured_validators[-1]
    assert validator(gl.vm.VMError('out of gas')) is False


def test_expected_failure_must_match(harness):
    from genlayer import gl
    def derive():
        raise gl.vm.UserError('[EXPECTED] invalid task')
    assert harness.signet._agrees(gl.vm.UserError('[EXPECTED] invalid task'), derive) is True
    assert harness.signet._agrees(gl.vm.UserError('[EXPECTED] other'), derive) is False


def test_unavailable_remains_unknown_after_three_reserved_attempts(harness):
    h = harness
    h.make()
    h.vm.clear_mocks()
    for m in h.manifests:
        for s in m['sources']:
            h.vm.mock_web(s['url'], {'status':503,'body':b''})
    for i in range(3):
        r = h.evaluate(finalize=False)
        assert r['attempts'] == i + 1
        assert h.vm.run_validator() is True
    assert r['status'] == 'ASSESSED'
    with h.vm.prank(h.resolver_address):
        h.signet.confirm_relation('r1')
    assert h.deliver()['status'] == 'REFUSED_UNRESOLVED'
    h.signet.evaluate('r1')
    assert h.signet.get_relation('r1')['attempts'] == 3


def test_rejected_model_exhaustion_is_persisted(harness):
    h = harness
    h.make()
    h.vm._llm_mocks.clear()
    h.vm.mock_llm('SIGNET_IDENTITY_EXTRACTION_V1', '{}')
    for i in range(3):
        with h.vm.expect_revert():
            h.evaluate(finalize=False)
        assert h.signet.get_relation('r1')['attempts'] == i + 1
    h.signet.evaluate('r1')
    h.world.run_next('confirm_relation')
    result = h.signet.get_relation('r1')
    assert result['status'] == 'FINALIZED'
    assert result['decision_vector']['unresolved'] == ['RETRY_EXHAUSTED']
