from copy import deepcopy
from scripts.envelopes import canonical, digest
import pytest


def test_callbacks_and_acknowledgements_idempotent(harness):
    h = harness
    h.make();h.evaluate()
    first = h.deliver()
    capacity = h.consumer.get_capacity('right')
    h.deliver()
    assert h.consumer.get_capacity('right') == capacity
    assert h.consumer.get_acknowledgement('r1') == first['acknowledgement']
    assert h.signet.get_delivery(str(h.consumer_address),'r1')['status'] == 'ACKNOWLEDGED'
    h.signet.reconcile_delivery(str(h.consumer_address),'r1')
    assert h.signet.get_delivery(str(h.consumer_address),'r1')['attempts'] == 1


def test_forged_callback_sender_rejected(harness):
    h = harness
    h.make();h.evaluate()
    certificate = {'source_contract':str(h.resolver_address),'consumer':str(h.consumer_address),'operation_id':'r1','relation':h.signet.get_relation('r1')}
    with h.vm.expect_revert('only authenticated resolver'):
        h.consumer.receive_certificate(canonical(certificate))
    with h.vm.expect_revert('only consumer acknowledgement'):
        h.signet.acknowledge(str(h.consumer_address),'r1','{}')


def test_pre_finality_self_and_attempt_calls_rejected(harness):
    h = harness
    h.make()
    with h.vm.expect_revert('only finalized self-message'):
        h.signet.confirm_relation('r1')
    with h.vm.expect_revert('only finalized attempt message'):
        h.signet.assess_attempt('r1',1)


def test_callback_binding_conflict(harness):
    h = harness
    h.make();h.evaluate();h.deliver()
    certificate = {'source_contract':str(h.resolver_address).lower(),'consumer':str(h.consumer_address).lower(),'operation_id':'r1','relation':h.signet.get_relation('r1')}
    certificate['relation']['bindings']['consequence_digest']='0'*64
    with h.vm.prank(h.resolver_address), h.vm.expect_revert('conflicting callback replay'):
        h.consumer.receive_certificate(canonical(certificate))


def test_source_revision_invalidates_alias_and_consumer(harness):
    h = harness
    h.make();h.evaluate();h.deliver()
    cid = h.signet.register_alias('left','r1')
    s = deepcopy(h.manifests[0]['sources'][0]);s['revision']=2
    h.signet.attest_source(canonical(s))
    assert h.signet.get_relation('r1')['active'] is False
    assert h.consumer.get_operation('r1')['effective_status'] == 'QUARANTINED'
    assert h.signet.get_alias('left')['active'] is False
    assert h.signet.get_cluster(cid)['members'] == ['left','right']
    with h.vm.expect_revert('active finalized relation'):
        h.signet.publish_to('r1',str(h.consumer_address),'later')


@pytest.mark.parametrize('category,item', [('relation','r1'),('source','r1-0:1'),('policy','obligation:1'),('authority','issuer'),('consumer',None)])
def test_quarantine_at_action_time(harness, category, item):
    h = harness
    h.make();h.evaluate()
    relation = h.signet.get_relation('r1')
    certificate = {'source_contract':str(h.resolver_address).lower(),'consumer':str(h.consumer_address).lower(),'operation_id':'r1','relation':relation}
    h.signet.quarantine(category,item or str(h.consumer_address))
    with h.vm.prank(h.resolver_address):
        h.consumer.receive_certificate(canonical(certificate))
    assert h.consumer.get_operation('r1')['effective_status'] == 'QUARANTINED'
    assert h.consumer.get_capacity('right')['held_minor'] == 12500


def test_supersede_mistaken_alias_retains_ids_and_references(harness):
    h = harness
    h.make();h.evaluate();h.deliver()
    cid = h.signet.register_alias('left','r1')
    h.consumer.release('r1')
    h.vm.clear_mocks()
    h.make('r2',changes={'period':'2026-11'},supersedes='r1')
    h.evaluate('r2');h.deliver('r2')
    old = h.signet.get_relation('r1')
    assert old['status'] == 'SUPERSEDED' and old['superseded_by'] == 'r2'
    assert h.signet.get_cluster(cid)['active'] is False
    assert h.signet.get_alias('left')['canonical_id'] == 'left'
    assert h.signet.get_alias('right')['canonical_id'] == 'right'
    assert h.consumer.get_operation('r1')['bindings']['request_id'] == 'r1'
    assert h.consumer.get_operation('r2')['status'] == 'REFUSED_DISTINCT'


def test_distinct_vetoes_later_same_without_explicit_supersession(harness):
    h = harness
    h.make(changes={'period':'2026-11'});h.evaluate()
    h.vm.clear_mocks()
    h.make('r2',prepare=False);h.evaluate('r2')
    assert h.signet.register_alias('left','r2') == 'UNRESOLVED_DISTINCT_EDGE'


def test_unknown_successor_cannot_clear_known_distinct(harness):
    h = harness
    h.make(changes={'period':'2026-11'});h.evaluate()
    h.vm.clear_mocks()
    h.make('r2',prepare=False,missing='period',supersedes='r1');h.evaluate('r2')
    h.vm.clear_mocks()
    h.make('r3',prepare=False);h.evaluate('r3')
    assert h.signet.register_alias('left','r3') == 'UNRESOLVED_DISTINCT_EDGE'


def test_explicit_same_successor_can_correct_distinct(harness):
    h = harness
    h.make(changes={'period':'2026-11'});h.evaluate()
    h.vm.clear_mocks()
    h.make('r2',prepare=False,supersedes='r1');h.evaluate('r2')
    assert h.signet.register_alias('left','r2') != 'UNRESOLVED_DISTINCT_EDGE'


def pair(h, request, a, b):
    h.vm.clear_mocks()
    h.make(request,a,b,prepare=False)
    h.evaluate(request)


def test_cross_cluster_requires_all_pairs(harness):
    h = harness
    pair(h,'ab','a','b');h.signet.register_alias('a','ab')
    pair(h,'bc','b','c')
    assert h.signet.register_alias('b','bc') == 'UNRESOLVED_CROSS_WITNESS'
    pair(h,'ac','a','c')
    h.signet.register_alias('a','ac')
    assert h.signet.get_alias('c')['members'] == ['a','b','c']


def test_cluster_bound_and_cross_scope(harness):
    h = harness
    for request,a,b in [('ab','a','b'),('ac','a','c'),('bc','b','c'),('ad','a','d'),('bd','b','d'),('cd','c','d')]:
        pair(h,request,a,b)
    h.signet.register_alias('a','ab')
    h.signet.register_alias('a','ac')
    h.signet.register_alias('a','ad')
    pair(h,'ae','a','e')
    assert h.signet.register_alias('a','ae') == 'UNRESOLVED_CLUSTER_BOUND'


def test_pending_holds_count_and_owner_alone_releases(harness):
    h = harness
    h.make()
    assert h.consumer.get_capacity('right')['held_minor'] == 12500
    with h.vm.prank(h.bob), h.vm.expect_revert('only reservation owner'):
        h.consumer.release('r1')
    h.consumer.release('r1');h.consumer.release('r1')
    assert h.consumer.get_capacity('right')['held_minor'] == 0


def test_integer_limits_and_capacity_pending(harness):
    h = harness
    for value in [0,-1,2**256]:
        with h.vm.expect_revert('capacity integer overflow'):
            h.consumer.register_economic_id('large',value)
    h.consumer.register_economic_id('large',2**256-1)
    assert h.consumer.get_capacity('large')['capacity_minor'] == 2**256-1
    h.make()
    for value in [0,-1,2**256]:
        with h.vm.expect_revert('amount integer overflow'):
            h.consumer.reserve('another',canonical(h.envelope),'right',value)
    e = deepcopy(h.envelope);e['subject_id']='new';e['request_id']='new';e['generation']=1
    value = 1000000
    e['consequence_digest'] = digest({'action':'RESERVE_EXISTING','economic_id':'right','amount_minor':value,'reservation_owner':str(h.alice).lower()})
    with h.vm.expect_revert('capacity exceeded including pending'):
        h.consumer.reserve('new',canonical(e),'right',value)


def test_old_callback_cannot_clear_newer_restriction(harness):
    h = harness
    h.make();h.evaluate()
    old = {'source_contract':str(h.resolver_address).lower(),'consumer':str(h.consumer_address).lower(),'operation_id':'r1','relation':h.signet.get_relation('r1')}
    h.consumer.release('r1')
    h.vm.clear_mocks();h.make('r2',changes={'period':'2026-11'});h.evaluate('r2');h.deliver('r2')
    with h.vm.prank(h.resolver_address):
        h.consumer.receive_certificate(canonical(old))
    assert h.consumer.get_operation('r2')['status'] == 'REFUSED_DISTINCT'
    assert h.consumer.get_operation('r1')['status'] == 'RELEASED'
    assert h.consumer.get_capacity('right')['held_minor'] == 12500


def test_delivery_retries_bounded_and_reconcilable(harness):
    h = harness
    h.make();h.evaluate()
    h.signet.publish_to('r1',str(h.consumer_address),'r1')
    for _ in range(3):
        h.signet.reconcile_delivery(str(h.consumer_address),'r1')
    delivery = h.signet.get_delivery(str(h.consumer_address),'r1')
    assert delivery['attempts'] == 3 and delivery['status'] == 'UNRESOLVED_DELIVERY'
    h.world.drain()
    assert h.signet.get_delivery(str(h.consumer_address),'r1')['status'] == 'ACKNOWLEDGED'


def test_reconcile_lost_ack_by_operation(harness):
    h = harness
    h.make();h.evaluate()
    h.signet.publish_to('r1',str(h.consumer_address),'r1')
    h.world.run_next('receive_certificate')
    h.signet.reconcile_delivery(str(h.consumer_address),'r1')
    assert h.signet.get_delivery(str(h.consumer_address),'r1')['status'] == 'ACKNOWLEDGED'


def test_new_distinct_revokes_old_same_consequence(harness):
    h=harness
    h.make();h.evaluate();h.deliver()
    h.vm.clear_mocks();h.make('contrary',prepare=False,changes={'period':'2026-11'});h.evaluate('contrary')
    assert h.signet.get_relation('r1')['active'] is False
    assert h.consumer.get_operation('r1')['effective_status']=='QUARANTINED'


def test_correcting_one_distinct_cannot_erase_another(harness):
    h=harness
    h.make('d1',prepare=False,changes={'period':'2026-11'});h.evaluate('d1')
    h.vm.clear_mocks();h.make('d2',prepare=False,changes={'period':'2026-12'});h.evaluate('d2')
    h.vm.clear_mocks();h.make('s1',prepare=False,supersedes='d2');h.evaluate('s1')
    assert h.signet.register_alias('left','s1')=='UNRESOLVED_DISTINCT_EDGE'
    assert h.signet.get_relation('s1')['active'] is False


def test_distinct_history_bound_returns_unresolved(harness):
    h=harness
    for i in range(17):
        h.vm.clear_mocks()
        rid='d'+str(i)
        h.make(rid,prepare=False,changes={'period':'2027-'+str(i+1)});h.evaluate(rid)
    h.vm.clear_mocks();h.make('same',prepare=False);h.evaluate('same')
    assert h.signet.register_alias('left','same')=='UNRESOLVED_DISTINCT_BOUND'


def test_policy_revision_cannot_bypass_known_distinct(harness):
    h=harness
    h.make('old',prepare=False,changes={'period':'2026-11'});h.evaluate('old')
    h.signet.register_policy(h.policy,2,h.schema,'obligation')
    h.consumer=h.world.deploy('contracts/receivable.py',str(h.resolver_address),h.policy,2,h.schema)
    h.consumer_address=h.consumer.address
    with h.vm.prank(h.consumer_address):
        h.signet.register_consumer(str(h.consumer_address),canonical({'policy_id':h.policy,'policy_revision':2,'schema_id':h.schema,'unresolved_consequence':'KEEP_HOLD'}))
    h.policy_revision=2
    h.vm.clear_mocks();h.make('new',prepare=False);h.evaluate('new')
    assert h.signet.register_alias('left','new')=='UNRESOLVED_DISTINCT_EDGE'
