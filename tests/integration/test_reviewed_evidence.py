"""Verify receipts from the real deployed Studio suite and safety transactions.

Run after scripts.run_batch, scripts.verify_studio and scripts.verify_safety.
These tests consume real network evidence; they do not substitute a model or VM.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import pytest
from gltest.assertions import tx_execution_succeeded
from scripts.envelopes import digest

ROOT = Path(os.environ.get('SIGNET_EVIDENCE_DIR', 'evidence/studio-reviewed'))


def saved(name):
    return json.loads((ROOT / name).read_text())


@pytest.mark.parametrize('role,filename', [('resolver','signet.py'), ('receivable','receivable.py'), ('incident','incident.py'), ('organization_policy_receiver','receivable.py')])
def test_deployed_sources_match_fixed_contracts(role, filename):
    assert saved('verification-result.json')['deployed_code_matches'] is True
    code = saved(role + '.code.json')['rpc_result']
    raw = bytes.fromhex(code[2:]) if code.startswith('0x') else base64.b64decode(code, validate=True)
    assert raw == Path('contracts', filename).read_bytes()
    assert saved('deployment.json')['contract_sha256'][filename] == hashlib.sha256(raw).hexdigest()


def test_real_consensus_and_finalized_consumer_delivery_for_all_cases():
    profiles = saved('execution-profiles.json')
    assert len(profiles) == 11
    for name, profile in profiles.items():
        assert profile['leader_only'] is False
        assert sum(v['vote'] == 'agree' for v in profile['validators']) >= 2
        assert saved(name + '.delivery.json')['status'] == 'ACKNOWLEDGED'
        consumer = saved(name + '.consumer.json')
        expected = 'QUARANTINED' if name.startswith('organization-') or name == 'name-only' else 'PERMITTED' if profile['relation'] == 'SAME' else 'REFUSED_UNRESOLVED' if profile['relation'] == 'UNKNOWN' else 'REFUSED_DISTINCT'
        assert consumer['effective_status'] == expected
        for side, field in enumerate(['left_manifest', 'right_manifest']):
            bundle = saved(name + '.request.json')
            operation = saved('manifest-' + name + '-' + str(side) + '.operation.json')
            assert operation['method'] == 'approve_record_manifest'
            assert json.loads(operation['args'][1]) == bundle[field]
            assert operation['sender'].lower() in bundle['envelope']['parties']
            assert tx_execution_succeeded(saved('manifest-' + name + '-' + str(side) + '.receipt.json'))


def test_live_source_ownership_and_revoked_correction_keep_application_safe():
    assert not tx_execution_succeeded(saved('safety-source-takeover.receipt.json'))
    assert saved('source-takeover-regression.json')['consumer']['effective_status'] == 'PERMITTED'
    assert saved('correction-before-revocation.json')['consumer']['effective_status'] == 'PERMITTED'
    after = saved('correction-after-revocation.json')
    assert after['consumer']['effective_status'] == 'QUARANTINED'
    assert after['capacity']['held_minor'] == 12500
    unbound = saved('revoked-correction-regression.json')
    assert unbound['unbound_relation']['decision_vector']['relation'] == 'SAME'
    assert unbound['unbound_relation']['active'] is False
    assert unbound['unmerged_alias']['cluster_id'] == ''


def test_live_alias_cluster_retains_exact_witness_dependencies():
    assert saved('alias-before-replacement.json')['active'] is True
    after = saved('alias-replacement-regression.json')
    assert after['alias']['active'] is False and after['cluster']['active'] is False
    assert len(after['cluster']['witnesses']) == 3
    assert after['unchanged_edge_remains_active'] is True
    assert saved('safety-verification-result.json')['additional_independently_agreed_assessments'] == 6
    for name in ['safety-correction','safety-unbound-same','safety-ab','safety-bc','safety-ac','safety-ab-replacement']:
        assert tx_execution_succeeded(saved('evaluate-' + name + '.receipt.json'))
        assessment = saved('evaluate-' + name + '-message-0.receipt.json')
        assert assessment['leader_only'] is False
        assert sum(v.get('vote') == 'agree' for v in assessment['consensus_data']['validators']) >= 2
