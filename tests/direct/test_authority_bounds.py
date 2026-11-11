from copy import deepcopy
import pytest
from scripts.envelopes import canonical, digest


@pytest.mark.parametrize('method,args', [
    ('register_identity_schema',('bad', ['official_id','jurisdiction'])),
    ('register_policy',('bad',1,'obligation:v1','economic')),
    ('set_assessor',('0x'+'1'*40,True)),
    ('quarantine',('policy','obligation:1')),
    ('register_authority',('new','0x'+'1'*40,'https://other.org/','https://other.org/authority')),
])
def test_owner_permissions(harness, method, args):
    h = harness
    with h.vm.prank(h.bob), h.vm.expect_revert('only owner'):
        getattr(h.signet, method)(*args)


def test_only_principal_can_attest(harness):
    harness.make()
    source = harness.manifests[0]['sources'][0]
    with harness.vm.prank(harness.bob), harness.vm.expect_revert('only source principal'):
        harness.signet.attest_source(canonical(source))


def test_assessor_cannot_approve_consumer(harness):
    with harness.vm.expect_revert('consumer must approve'):
        harness.signet.register_consumer(str(harness.consumer_address),canonical({'policy_id':'obligation','policy_revision':1,'schema_id':'obligation:v1','unresolved_consequence':'KEEP_HOLD'}))


@pytest.mark.parametrize('fields', [['name'],['name','address'],['official_id'],['payer_id','period'],['official_id','jurisdiction','biometric'],['official_id','official_id','jurisdiction'],['name']*9])
def test_no_name_only_or_private_schemas(harness, fields):
    with harness.vm.expect_revert():
        harness.signet.register_identity_schema('bad', fields)


def test_request_unique_identical_idempotent_conflicting_refused(harness):
    h = harness
    e, manifests = h.make()
    args = ('r1',h.schema,canonical(manifests[0]),canonical(manifests[1]),canonical(e))
    h.signet.compare_records(*args)
    e2 = deepcopy(e)
    e2['generation'] += 1
    with h.vm.expect_revert('conflicting request ID'):
        h.signet.compare_records(*args[:-1],canonical(e2))
    assert h.signet.get_relation('r1')['bindings'] == e


@pytest.mark.parametrize('field,value,error', [('byte_length',49153,'source byte limit'),('revision',2**64,'source revision overflow'),('channel','PRIVATE','source outside'),('url','https://evil.org/doc','source outside'),('raw_hash','abc','invalid digest')])
def test_source_limits(harness, field, value, error):
    h = harness
    h.make()
    s = deepcopy(h.manifests[0]['sources'][0])
    s[field] = value
    with h.vm.expect_revert(error):
        h.signet.attest_source(canonical(s))


@pytest.mark.parametrize('field,value,error', [('generation',2**64,'generation overflow'),('generation',0,'generation overflow'),('deadline',2**64,'deadline overflow'),('deadline',0,'deadline expired'),('consequence_digest','bad','invalid digest'),('subject_digest','0'*64,'subject digest mismatch'),('source_manifest_digest','0'*64,'manifest digest mismatch'),('parties',[],'principal parties binding')])
def test_envelope_bounds(harness, field, value, error):
    h = harness
    e,m = h.make()
    e = deepcopy(e)
    e['request_id'] = 'r2'
    e[field] = value
    with h.vm.expect_revert(error):
        h.signet.compare_records('r2',h.schema,canonical(m[0]),canonical(m[1]),canonical(e))


def test_deadline_uses_transaction_time(harness):
    h = harness
    h.make()
    h.vm.warp('2034-01-01T00:00:00Z')
    h.signet.evaluate('r1')
    assert h.signet.get_relation('r1')['status'] == 'TIMEOUT'


def test_paginated_revision_indexes(harness):
    h = harness
    h.make()
    assert h.signet.revision_relations('source','r1-0:1',0,100) == ['r1']
    assert h.signet.revision_relations('policy','obligation:1',0,1) == ['r1']
    assert h.signet.revision_relations('subject','left',0,1) == ['r1']
    assert len(h.signet.history_page(0,100)) >= 7
    for args in [(-1,1),(0,0),(0,101)]:
        with h.vm.expect_revert('pagination bounds'):
            h.signet.history_page(*args)


def test_policy_and_source_revision_immutable(harness):
    h = harness
    h.make()
    with h.vm.expect_revert('conflicting policy revision'):
        h.signet.register_policy(h.policy,1,h.schema,'other')
    source = deepcopy(h.manifests[0]['sources'][0]);source['raw_hash']='0'*64
    with h.vm.expect_revert('conflicting source revision'):
        h.signet.attest_source(canonical(source))
