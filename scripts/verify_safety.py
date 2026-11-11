"""Execute journaled authorization and correction/alias regressions on Studio."""
from copy import deepcopy
import json
import os
from pathlib import Path
from gltest.assertions import tx_execution_succeeded
from scripts.envelopes import canonical, digest, request_envelope, source_manifest
from scripts.run_studio import credentials
from scripts.studio import Studio, atomic_json
from scripts.verify_studio import collect_children

ROOT = Path(os.environ.get('SIGNET_EVIDENCE_DIR', 'evidence/studio-reviewed'))


def assess(owner, resolver, request_id, manifests, consumer, generation, supersedes=''):
    consequence = {'action': 'RESERVE_EXISTING', 'economic_id': manifests[1]['subject_id'], 'amount_minor': 12500, 'reservation_owner': owner.principal_address.lower()}
    e = request_envelope(request_id, owner.account.address, [owner.principal_address], 'obligation', 1, manifests[0], manifests[1], consumer, consequence, generation, 2000000000, supersedes)
    atomic_json(ROOT / (request_id + '.request.json'), {'envelope': e, 'left_manifest': manifests[0], 'right_manifest': manifests[1], 'consequence': consequence, 'synthetic': True})
    owner.transaction('compare-' + request_id, resolver, 'compare_records', [request_id, 'obligation:v1', canonical(manifests[0]), canonical(manifests[1]), canonical(e)])
    receipt = owner.transaction('evaluate-' + request_id, resolver, 'evaluate', [request_id])
    relation_path = ROOT / (request_id + '.relation.json')
    result = json.loads(relation_path.read_text()) if relation_path.exists() else owner.wait_relation(resolver, request_id)
    assert result['bindings'] == e
    children = collect_children(owner, receipt, 'evaluate-' + request_id)
    assert result['status'] == 'FINALIZED'
    assert result['decision_vector']['relation'] == 'SAME'
    assert len(children) >= 2
    validators = children[0]['consensus_data']['validators']
    assert sum(r.get('vote') == 'agree' for r in validators) >= 2
    return e, result


def approve(principal, resolver, label, manifests):
    for side, manifest in enumerate(manifests):
        for source in manifest['sources']:
            principal.transaction('attest-' + label + '-' + str(side), resolver, 'attest_source', [canonical(source)])
        principal.transaction('manifest-' + label + '-' + str(side), resolver, 'approve_record_manifest', ['obligation', canonical(manifest)])


def run():
    assert json.loads((ROOT / 'verification-result.json').read_text())['deployed_code_matches'] is True
    state = json.loads((ROOT / 'deployment.json').read_text())
    keys = credentials()
    owner, principal = Studio(keys['deployer_key'], str(ROOT)), Studio(keys['receivable_key'], str(ROOT))
    owner.principal_address = principal.account.address
    resolver, consumer = state['resolver'], state['receivable']
    corpus = json.loads(Path('evidence/public-sources.json').read_text())
    same_records = next(c for c in corpus['cases'] if c['case_id'] == 'invoice-reissue')['records']

    # A second configured principal must not advance another principal's source head.
    bundle = json.loads((ROOT / 'invoice-reissue.request.json').read_text())
    replacement = deepcopy(bundle['left_manifest']['sources'][0])
    replacement.update({'revision': 2, 'subject_id': 'unauthorized-takeover', 'authority_id': 'deployer'})
    failed = owner.transaction('safety-source-takeover', resolver, 'attest_source', [canonical(replacement)], require_success=False)
    assert not tx_execution_succeeded(failed)
    takeover = {'relation': owner.read(resolver, 'get_relation', ['invoice-reissue']), 'consumer': principal.read(consumer, 'get_operation', ['invoice-reissue'])}
    assert takeover['relation']['active'] is True and takeover['consumer']['effective_status'] == 'PERMITTED'
    atomic_json(ROOT / 'source-takeover-regression.json', takeover)

    # Correct one DISTINCT ruling, deliver its SAME correction, then revoke that correction.
    negative = json.loads((ROOT / 'invoice-next-month.request.json').read_text())
    manifests = [deepcopy(negative['left_manifest']), deepcopy(negative['right_manifest'])]
    for side, manifest in enumerate(manifests):
        old = manifest['sources'][0]
        public = same_records[side]
        manifest['sources'] = [source_manifest(old['source_id'], manifest['subject_id'], 'receivable', public['url'], public['content'].encode(), 'obligation', revision=2)]
    approve(principal, resolver, 'safety-correction', manifests)
    request_id = 'safety-correction'
    principal.transaction('release-before-' + request_id, consumer, 'release', ['invoice-next-month'])
    consequence = {'action': 'RESERVE_EXISTING', 'economic_id': manifests[1]['subject_id'], 'amount_minor': 12500, 'reservation_owner': principal.account.address.lower()}
    e = request_envelope(request_id, owner.account.address, [principal.account.address], 'obligation', 1, manifests[0], manifests[1], consumer, consequence, 2, 2000000000, 'invoice-next-month')
    principal.transaction('prepare-' + request_id, consumer, 'reserve', [request_id, canonical(e), e['right_subject_id'], 12500])
    _, result = assess(owner, resolver, request_id, manifests, consumer, 2, 'invoice-next-month')
    publish = owner.transaction('publish-' + request_id, resolver, 'publish_to', [request_id, consumer, request_id])
    owner.wait_delivery(resolver, consumer, request_id)
    assert len(collect_children(owner, publish, 'publish-' + request_id)) >= 2
    before_path = ROOT / 'correction-before-revocation.json'
    if not before_path.exists():
        permitted = principal.read(consumer, 'get_operation', [request_id])
        assert permitted['effective_status'] == 'PERMITTED'
        owner.transaction('alias-' + request_id, resolver, 'register_alias', [e['subject_id'], request_id])
        alias = owner.read(resolver, 'get_alias', [e['subject_id']]); assert alias['active']
        atomic_json(before_path, {'relation': result, 'consumer': permitted, 'alias': alias})
    owner.transaction('quarantine-' + request_id, resolver, 'quarantine', ['relation', request_id])
    checkpoint = ROOT / 'correction-after-revocation.json'
    if not checkpoint.exists():
        revoked = principal.read(consumer, 'get_operation', [request_id])
        capacity = principal.read(consumer, 'get_capacity', [e['right_subject_id']])
        assert revoked['effective_status'] == 'QUARANTINED' and capacity['held_minor'] == 12500
        atomic_json(checkpoint, {'consumer': revoked, 'capacity': capacity, 'alias': owner.read(resolver, 'get_alias', [e['subject_id']])})
    _, unbound = assess(owner, resolver, 'safety-unbound-same', manifests, consumer, 3)
    assert unbound['active'] is False
    owner.transaction('alias-safety-unbound', resolver, 'register_alias', [e['subject_id'], 'safety-unbound-same'])
    unmerged = owner.read(resolver, 'get_alias', [e['subject_id']])
    assert unmerged['canonical_id'] == e['subject_id'] and unmerged['cluster_id'] == ''
    atomic_json(ROOT / 'revoked-correction-regression.json', {'unbound_relation': unbound, 'unmerged_alias': unmerged, 'corrected_negative': 'invoice-next-month'})
    principal.transaction('release-' + request_id, consumer, 'release', [request_id])

    # Every cluster edge is bound to its exact witness, including after replacement.
    clique = []
    for side in range(3):
        subject = 'safety-alias-' + str(side)
        public = same_records[0]
        clique.append({'subject_id': subject, 'sources': [source_manifest(subject, subject, 'receivable', public['url'], public['content'].encode(), 'obligation')]})
    for index, manifest in enumerate(clique): approve(principal, resolver, 'clique-' + str(index), [manifest])
    assess(owner, resolver, 'safety-ab', [clique[0], clique[1]], consumer, 1)
    owner.transaction('alias-safety-ab', resolver, 'register_alias', [clique[0]['subject_id'], 'safety-ab'])
    assess(owner, resolver, 'safety-bc', [clique[1], clique[2]], consumer, 1)
    assess(owner, resolver, 'safety-ac', [clique[0], clique[2]], consumer, 2)
    owner.transaction('alias-safety-ac', resolver, 'register_alias', [clique[0]['subject_id'], 'safety-ac'])
    prior_path = ROOT / 'alias-before-replacement.json'
    if not prior_path.exists():
        prior = owner.read(resolver, 'get_alias', [clique[2]['subject_id']]); assert prior['active'] and len(prior['members']) == 3
        atomic_json(prior_path, prior)
    assess(owner, resolver, 'safety-ab-replacement', [clique[0], clique[1]], consumer, 3)
    after = owner.read(resolver, 'get_alias', [clique[2]['subject_id']])
    assert not after['active'] and after['canonical_id'] == clique[2]['subject_id']
    assert owner.read(resolver, 'get_relation', ['safety-bc'])['active'] is True
    prior = json.loads(prior_path.read_text())
    cluster = owner.read(resolver, 'get_cluster', [prior['cluster_id']]); assert not cluster['active']
    atomic_json(ROOT / 'alias-replacement-regression.json', {'alias': after, 'cluster': cluster, 'unchanged_edge_remains_active': True})
    atomic_json(ROOT / 'safety-verification-result.json', {'executed': True, 'network': 'studionet', 'synthetic': True, 'source_takeover_rejected': True, 'revoked_correction_restores_veto': True, 'exact_alias_witness_dependencies_enforced': True, 'additional_independently_agreed_assessments': 6})


if __name__ == '__main__': run()
