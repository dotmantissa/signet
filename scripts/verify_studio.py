"""Verify real assessment/message receipts and recovery after the Studio suite.

Run only after scripts.run_batch succeeds. The optional state probes quarantine
one synthetic test relation and release its test reservation after recording the
original suite result. All writes are journaled and safe to resume.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

from scripts.run_studio import credentials
from scripts.studio import Studio, atomic_json


ROOT = Path(os.environ.get('SIGNET_EVIDENCE_DIR', 'evidence/studio-reviewed'))


def collect_children(session, receipt, label):
    children = []
    for index, tx in enumerate(receipt.get('triggered_transactions', [])):
        child_label = label + '-message-' + str(index)
        child = session.wait(tx, child_label)
        assert child.get('leader_only') is False, child_label + ': leader-only execution'
        children.append(child)
        children.extend(collect_children(session, child, child_label))
    return children


def participant_profile(receipt):
    return {
        'vote': receipt.get('vote'),
        'model': receipt.get('node_config', {}).get('primary_model', {}).get('model'),
        'gas_used': receipt.get('gas_used'),
        'processing_time_reported': receipt.get('processing_time'),
        'execution_stats': receipt.get('execution_stats', {}),
        'nondet_disagree': receipt.get('nondet_disagree'),
        'execution_result': receipt.get('execution_result'),
    }


def verify(probes=False):
    suite = json.loads((ROOT / 'suite-result.json').read_text())
    assert suite['executed'] is True
    state = json.loads((ROOT / 'deployment.json').read_text())
    keys = credentials()
    owner = Studio(keys['deployer_key'], str(ROOT))
    profiles = {}
    for case_id in suite['cases']:
        evaluate = json.loads((ROOT / ('evaluate-' + case_id + '.receipt.json')).read_text())
        children = collect_children(owner, evaluate, 'evaluate-' + case_id)
        assert len(children) >= 2, case_id + ': missing assessment or finality message'
        assessment = children[0]
        consensus = assessment['consensus_data']
        validators = consensus.get('validators', [])
        assert len(validators) >= 2, case_id + ': missing validator receipts'
        agreeing = [r for r in validators if r.get('vote') == 'agree']
        assert len(agreeing) >= 2, case_id + ': insufficient independent agreement'
        relation = json.loads((ROOT / (case_id + '.relation.json')).read_text())
        bundle = json.loads((ROOT / (case_id + '.request.json')).read_text())
        directory_path = ROOT / (case_id + '.directory.json')
        if directory_path.exists():
            directory = json.loads(directory_path.read_text())
            expected_id = bundle['envelope']['right_subject_id'] if suite['cases'][case_id] == 'SAME' else bundle['envelope']['subject_id']
            assert directory['canonical_id'] == expected_id, case_id + ': incorrect directory mapping'
        profiles[case_id] = {
            'transaction_hash': assessment['hash'],
            'relation': relation['decision_vector']['relation'],
            'availability': relation['decision_vector']['availability'],
            'complete_source_bytes': sum(s['byte_length'] for m in [bundle['left_manifest'], bundle['right_manifest']] for s in m['sources']),
            'leader_only': assessment.get('leader_only'),
            'rotation_count': assessment.get('rotation_count'),
            'num_of_rounds': assessment.get('num_of_rounds'),
            'leader': [participant_profile(r) for r in consensus.get('leader_receipt', [])],
            'validators': [participant_profile(r) for r in validators],
            'votes': consensus.get('votes'),
        }
        publish = json.loads((ROOT / ('publish-' + case_id + '.receipt.json')).read_text())
        callbacks = collect_children(owner, publish, 'publish-' + case_id)
        assert len(callbacks) >= 2, case_id + ': missing consumer callback or acknowledgement'
        print(case_id, 'CONSENSUS_AND_CALLBACKS_VERIFIED', flush=True)
    for kind in ['obligation', 'incident', 'organization']:
        receipt = json.loads((ROOT / ('approve-' + kind + '.receipt.json')).read_text())
        assert collect_children(owner, receipt, 'approve-' + kind)
    atomic_json(ROOT / 'execution-profiles.json', profiles)

    code_checks = {}
    for role, filename in [('resolver', 'signet.py'), ('receivable', 'receivable.py'), ('incident', 'incident.py'), ('organization_policy_receiver', 'receivable.py')]:
        address = state[role]
        # Studio exposes GenVM source separately from EVM eth_getCode.
        remote = owner.client.provider.make_request('gen_getContractCode', [address])['result']
        atomic_json(ROOT / (role + '.code.json'), {'method': 'gen_getContractCode', 'address': address, 'rpc_result': remote})
        if isinstance(remote, str):
            raw = bytes.fromhex(remote[2:]) if remote.startswith('0x') else base64.b64decode(remote, validate=True)
        else:
            raise AssertionError('Unexpected deployed code encoding')
        local = Path('contracts', filename).read_bytes()
        assert raw == local, role + ': deployed source differs from local file'
        schema = owner.client.get_contract_schema(address)
        atomic_json(ROOT / (role + '.schema.json'), schema)
        code_checks[role] = {'address': address, 'sha256': hashlib.sha256(raw).hexdigest(), 'matches_local': True}
    atomic_json(ROOT / 'code-verification.json', code_checks)
    atomic_json(ROOT / 'deployed-limits.json', owner.read(state['resolver'], 'limits'))

    if probes:
        consumer = Studio(keys['receivable_key'], str(ROOT))
        resolver, receiver, request = state['resolver'], state['receivable'], 'translation'
        delivery_before = owner.read(resolver, 'get_delivery', [receiver, request])
        owner.transaction('probe-repeat-publish', resolver, 'publish_to', [request, receiver, request])
        owner.transaction('probe-reconcile-ack', resolver, 'reconcile_delivery', [receiver, request])
        delivery_after = owner.read(resolver, 'get_delivery', [receiver, request])
        assert delivery_after == delivery_before and delivery_after['attempts'] == 1
        owner.transaction('probe-quarantine-relation', resolver, 'quarantine', ['relation', request])
        checkpoint = ROOT / 'quarantine-probe-checkpoint.json'
        if checkpoint.exists():
            snapshots = json.loads(checkpoint.read_text())
        else:
            original_alias = json.loads((ROOT / (request + '.alias.json')).read_text())
            snapshots = {
                'operation': consumer.read(receiver, 'get_operation', [request]),
                'capacity': consumer.read(receiver, 'get_capacity', [request + '-1']),
                'alias': owner.read(resolver, 'get_alias', [request + '-0']),
                'right_alias': owner.read(resolver, 'get_alias', [request + '-1']),
                'retired_cluster': owner.read(resolver, 'get_cluster', [original_alias['cluster_id']]),
            }
            assert snapshots['operation']['effective_status'] == 'QUARANTINED'
            assert snapshots['capacity']['held_minor'] == 12500
            assert snapshots['alias']['cluster_id'] == ''
            assert snapshots['alias']['canonical_id'] == request + '-0'
            assert snapshots['right_alias']['canonical_id'] == request + '-1'
            assert snapshots['retired_cluster']['active'] is False
            assert snapshots['retired_cluster']['superseded_by'] == request
            atomic_json(checkpoint, snapshots)
        consumer.transaction('probe-release-reservation', receiver, 'release', [request])
        consumer.transaction('probe-release-again', receiver, 'release', [request])
        released = consumer.read(receiver, 'get_capacity', [request + '-1'])
        assert released['held_minor'] == 0
        atomic_json(ROOT / 'recovery-probes.json', {
            'executed': True, 'synthetic': True,
            'repeated_publish_and_reconcile_preserve_delivery': delivery_after,
            'quarantined_operation': snapshots['operation'], 'quarantined_alias': snapshots['alias'],
            'retained_right_historical_id': snapshots['right_alias'],
            'retired_cluster': snapshots['retired_cluster'],
            'hold_retained_before_owner_release': snapshots['capacity'],
            'capacity_after_idempotent_owner_release': released,
            'post_suite_state_change': request + ' relation quarantined and its reservation released',
        })
    atomic_json(ROOT / 'verification-result.json', {'executed': True, 'real_consensus': True, 'cases': len(profiles), 'deployed_code_matches': True, 'recovery_probes': probes})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-probes', action='store_true')
    verify(parser.parse_args().state_probes)
