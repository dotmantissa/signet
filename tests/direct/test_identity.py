from scripts.envelopes import canonical
import pytest


def test_complete_same_and_finality(harness):
    h = harness
    h.make()
    result = h.evaluate(finalize=False)
    assert result['status'] == 'ASSESSED'
    with h.vm.expect_revert('active finalized relation required'):
        h.signet.publish_to('r1', str(h.consumer_address), 'r1')
    with h.vm.prank(h.resolver_address):
        h.signet.confirm_relation('r1')
    assert h.vm.run_validator() is True
    assert h.deliver()['effective_status'] == 'PERMITTED'
    assert h.signet.register_alias('left', 'r1') == h.signet.register_alias('left', 'r1')
    assert h.signet.get_alias('right')['canonical_id'] == 'left'


@pytest.mark.parametrize('field,value', [('period','2026-11'),('payer_id','reg:other'),('payee_id','reg:other'),('consideration','equipment rental'),('amount_minor','12501'),('currency','eur')])
def test_obligation_discriminators(harness, field, value):
    harness.make(changes={field: value})
    result = harness.evaluate()
    assert result['decision_vector']['relation'] == 'DISTINCT'
    assert harness.vm.run_validator() is True
    assert harness.deliver()['status'] == 'REFUSED_DISTINCT'


def test_reissued_identifier_does_not_change_obligation(harness):
    harness.make(flags={'identifier_reissued': True})
    assert harness.evaluate()['decision_vector']['relation'] == 'SAME'


@pytest.mark.parametrize('flag,relation', [('recurring','SAME'),('related_only','DISTINCT'),('scope_ambiguous','UNKNOWN'),('controlling_exception','DISTINCT')])
def test_scope_and_controlling_flags(harness, flag, relation):
    harness.make(flags={flag: True})
    assert harness.evaluate()['decision_vector']['relation'] == relation


def test_missing_identifier_never_name_only(harness):
    harness.make(missing='payer_id')
    result = harness.evaluate()
    assert result['decision_vector']['relation'] == 'UNKNOWN'
    assert harness.deliver()['status'] == 'REFUSED_UNRESOLVED'
    with harness.vm.expect_revert('finalized active SAME witness required'):
        harness.signet.register_alias('left', 'r1')


def test_renamed_incident_and_separate_occurrence(incident):
    incident.make()
    assert incident.evaluate()['decision_vector']['relation'] == 'SAME'
    assert incident.deliver()['effective_status'] == 'PERMITTED'
    assert incident.consumer.resolve_record('left')['canonical_id'] == 'right'
    incident.vm.clear_mocks()
    incident.make('r2', 'another', 'right', changes={'event_date':'2026-10-05','occurrence_id':'outage:43'})
    assert incident.evaluate('r2')['decision_vector']['relation'] == 'DISTINCT'
    assert incident.deliver('r2')['status'] == 'REFUSED_DISTINCT'
    assert incident.consumer.resolve_record('another')['canonical_id'] == 'another'


def test_same_name_organization_identifiers_control(organization):
    organization.make(changes={'official_id':'registry:992'})
    assert organization.evaluate()['decision_vector']['relation'] == 'DISTINCT'
