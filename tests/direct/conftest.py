import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.envelopes import canonical, source_manifest, request_envelope
from world import World

FIELDS = {
    'OBLIGATION': ['payer_id', 'payee_id', 'consideration', 'period', 'amount_minor', 'currency'],
    'INCIDENT': ['event_date', 'location_id', 'event_kind', 'occurrence_id'],
    'ORGANIZATION': ['official_id', 'jurisdiction'],
}
VALUES = {
    'OBLIGATION': ['reg:payer', 'reg:payee', 'monthly hosting', '2026-10', '12500', 'usd'],
    'INCIDENT': ['2026-10-04', 'terminal:4', 'power outage', 'outage:42'],
    'ORGANIZATION': ['registry:991', 'ng'],
}
FLAGS = ['related_only', 'identifier_reissued', 'recurring', 'scope_ambiguous', 'controlling_exception']


class Harness:
    def __init__(self, vm, deploy, alice, bob, kind='OBLIGATION'):
        self.vm, self.alice, self.bob, self.kind = vm, alice, bob, kind
        vm.sender = alice
        self.world = World(vm, deploy)
        deploy = self.world.deploy
        self.signet = deploy('contracts/signet.py')
        from genlayer import Address
        import genlayer.gl.genvm_contracts as runtime
        self.alice, self.bob = Address(alice), Address(bob)
        alice, bob = self.alice, self.bob
        self.resolver_address = self.signet.address
        self.schema = kind.lower() + ':v1'
        self.policy = kind.lower()
        self.policy_revision = 1
        self.signet.register_identity_schema(self.schema, FIELDS[kind])
        self.signet.register_policy(self.policy, 1, self.schema, kind.lower())
        contract = 'incident' if kind == 'INCIDENT' else 'receivable'
        self.consumer = deploy('contracts/' + contract + '.py', str(self.resolver_address), self.policy, 1, self.schema)
        self.consumer_address = self.consumer.address
        self.signet.register_authority('issuer', str(alice), 'https://records.example.org/', 'https://records.example.org/authority')
        with vm.prank(self.consumer_address):
            self.signet.register_consumer(str(self.consumer_address), canonical({'policy_id': self.policy, 'policy_revision': 1, 'schema_id': self.schema, 'unresolved_consequence': 'DO_NOT_LINK' if kind == 'INCIDENT' else 'KEEP_HOLD'}))
        self.generation = {}

    def make(self, request_id='r1', left_id='left', right_id='right', changes=None, flags=None, missing=None, generation=None, prepare=True, supersedes='', revision=1, extra_lines=None):
        values = dict(zip(FIELDS[self.kind], VALUES[self.kind]))
        side_values = [dict(values), dict(values)]
        if changes:
            side_values[1].update(changes)
        if missing:
            side_values[1][missing] = ''
        side_flags = [{f: False for f in FLAGS}, {f: False for f in FLAGS}]
        if flags:
            side_flags[1].update(flags)
        manifests, answers = [], []
        for side, subject in enumerate([left_id, right_id]):
            lines = [f'Synthetic public test record: {subject}\n']
            lines += [f'{k}: {v}\n' for k, v in side_values[side].items() if v]
            lines += [f'{k}: true\n' for k, v in side_flags[side].items() if v]
            if extra_lines:
                lines += [line + '\n' for line in extra_lines]
            raw = ''.join(lines).encode()
            sid = request_id + '-' + str(side)
            url = 'https://records.example.org/' + sid
            source = source_manifest(sid, subject, 'issuer', url, raw, self.kind.lower(), revision)
            self.signet.attest_source(canonical(source))
            manifests.append({'subject_id': subject, 'sources': [source]})
            self.vm.mock_web(url, {'status': 200, 'body': raw})
            witnesses = {}
            offset = 0
            for line in raw.splitlines(keepends=True):
                text = line.decode().strip()
                key = text.split(': ', 1)[0]
                witnesses[key] = source['raw_hash'] + ':' + str(offset) + ':' + str(offset + len(line))
                offset += len(line)
            answers.append({'fields': {k: {'value': v, 'spans': [witnesses[k]] if v else []} for k, v in side_values[side].items()}, 'flags': {k: {'value': v, 'spans': [witnesses[k]] if v else []} for k, v in side_flags[side].items()}})
        self.answer = {'sides': answers}
        self.vm.mock_llm('SIGNET_IDENTITY_EXTRACTION_V1', json.dumps(self.answer))
        gen = generation if generation is not None else self.generation.get(left_id, 0) + 1
        self.generation[left_id] = gen
        if self.kind == 'INCIDENT':
            consequence = {'action': 'LINK_INCIDENT', 'canonical_id': right_id, 'record_id': left_id, 'link_owner': str(self.alice).lower()}
        else:
            self.consumer.register_economic_id(right_id, 1000000)
            consequence = {'action': 'RESERVE_EXISTING', 'economic_id': right_id, 'amount_minor': 12500, 'reservation_owner': str(self.alice).lower()}
        e = request_envelope(request_id, str(self.alice), [str(self.alice)], self.policy, self.policy_revision, manifests[0], manifests[1], str(self.consumer_address), consequence, gen, 2000000000, supersedes)
        if prepare:
            if self.kind == 'INCIDENT':
                self.consumer.propose_link(request_id, canonical(e))
            else:
                self.consumer.reserve(request_id, canonical(e), right_id, 12500)
        self.signet.compare_records(request_id, self.schema, canonical(manifests[0]), canonical(manifests[1]), canonical(e))
        self.envelope, self.manifests = e, manifests
        return e, manifests

    def evaluate(self, request_id='r1', finalize=True):
        self.signet.evaluate(request_id)
        self.world.run_next('assess_attempt')
        if finalize:
            with self.vm.prank(self.resolver_address):
                self.signet.confirm_relation(request_id)
        return self.signet.get_relation(request_id)

    def deliver(self, request_id='r1', operation_id=None):
        op = operation_id or request_id
        relation = self.signet.get_relation(request_id)
        certificate = {'source_contract': str(self.resolver_address).lower(), 'consumer': str(self.consumer_address).lower(), 'operation_id': op, 'relation': relation}
        self.signet.publish_to(request_id, str(self.consumer_address), op)
        with self.vm.prank(self.resolver_address):
            self.consumer.receive_certificate(canonical(certificate))
        ack = self.consumer.get_acknowledgement(op)
        with self.vm.prank(self.consumer_address):
            self.signet.acknowledge(str(self.consumer_address), op, ack)
        return self.consumer.get_operation(op)


@pytest.fixture
def harness(direct_vm, direct_deploy, direct_alice, direct_bob):
    return Harness(direct_vm, direct_deploy, direct_alice, direct_bob)

@pytest.fixture
def incident(direct_vm, direct_deploy, direct_alice, direct_bob):
    return Harness(direct_vm, direct_deploy, direct_alice, direct_bob, 'INCIDENT')

@pytest.fixture
def organization(direct_vm, direct_deploy, direct_alice, direct_bob):
    return Harness(direct_vm, direct_deploy, direct_alice, direct_bob, 'ORGANIZATION')
