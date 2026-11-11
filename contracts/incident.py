# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
import hashlib
import json
import re
from datetime import datetime

MAX_U64 = 18446744073709551615
MAX_U256 = (1 << 256) - 1
MAX_OPERATIONS = 100000


def canon(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value) -> str:
    return hashlib.sha256(canon(value).encode('utf-8')).hexdigest()


def require(ok: bool, message: str) -> None:
    if not ok:
        raise gl.vm.UserError('[EXPECTED] ' + message)


def now_seconds() -> int:
    return int(datetime.fromisoformat(gl.message_raw['datetime'].replace('Z', '+00:00')).timestamp())


@allow_storage
@dataclass
class PendingOperation:
    envelope: str
    consequence: str
    owner: Address
    status: str
    payload_digest: str
    acknowledgement: str


class IncidentConsumer(gl.Contract):
    owner: Address
    resolver: Address
    policy_id: str
    policy_revision: u64
    schema_id: str
    parties: TreeMap[Address, bool]
    operations: TreeMap[str, PendingOperation]
    generations: TreeMap[str, u64]
    subject_operations: TreeMap[str, str]
    history: DynArray[str]
    count: u64

    applied_generations: TreeMap[str, u64]

    def __init__(self, resolver: str, policy_id: str, policy_revision: int, schema_id: str):
        require(1 <= policy_revision <= MAX_U64, 'policy revision overflow')
        self.owner = gl.message.sender_address
        self.resolver = Address(resolver)
        self.policy_id = policy_id
        self.policy_revision = u64(policy_revision)
        self.schema_id = schema_id
        self.parties[self.owner] = True
        self.count = u64(0)

    @gl.public.write
    def approve_configuration(self) -> None:
        require(gl.message.sender_address == self.owner, 'only owner')
        configuration = {'policy_id': self.policy_id, 'policy_revision': int(self.policy_revision), 'schema_id': self.schema_id, 'unresolved_consequence': 'DO_NOT_LINK'}
        gl.get_contract_at(self.resolver).emit(on='finalized').register_consumer(gl.message.contract_address.as_hex, canon(configuration))

    @gl.public.write
    def set_party(self, account: str, allowed: bool) -> None:
        require(gl.message.sender_address == self.owner, 'only owner')
        self.parties[Address(account)] = allowed

    def _prepare(self, operation_id: str, envelope_json: str, consequence: dict) -> bool:
        require(self.parties.get(gl.message.sender_address, False), 'party permission required')
        require(re.fullmatch(r'[A-Za-z0-9_.:-]{1,96}', operation_id) is not None, 'invalid operation ID')
        require(len(envelope_json.encode('utf-8')) <= 8192, 'envelope size limit')
        e = json.loads(envelope_json)
        required = {'request_id', 'owner', 'parties', 'policy_id', 'policy_revision', 'subject_id', 'right_subject_id', 'subject_digest', 'source_manifest_digest', 'consumer', 'consequence_digest', 'generation', 'deadline', 'supersedes'}
        require(set(e) == required, 'canonical envelope schema')
        require(Address(e['consumer']) == gl.message.contract_address and e['policy_id'] == self.policy_id and e['policy_revision'] == int(self.policy_revision), 'consumer policy binding')
        require(e['consequence_digest'] == digest(consequence), 'consequence binding mismatch')
        require(type(e['generation']) is int and 1 <= e['generation'] <= MAX_U64, 'generation overflow')
        require(type(e['deadline']) is int and 0 <= e['deadline'] <= MAX_U64, 'deadline expired or overflow')
        if operation_id in self.operations:
            p = self.operations[operation_id]
            require(p.owner == gl.message.sender_address and p.envelope == canon(e) and p.consequence == canon(consequence), 'conflicting operation ID reuse')
            return False
        require(now_seconds() <= e['deadline'], 'deadline expired or overflow')
        require(gl.get_contract_at(self.resolver).view().is_subject_authorized(e['subject_id'], gl.message.sender_address.as_hex), 'subject authorization required')
        require(int(self.count) < MAX_OPERATIONS, 'operation capacity reached')
        require(e['generation'] > int(self.generations.get(e['subject_id'], u64(0))), 'stale generation')
        previous = self.subject_operations.get(e['subject_id'], '')
        if previous:
            require(self.operations[previous].status == 'RELEASED', 'release previous operation before successor')
        self.generations[e['subject_id']] = u64(e['generation'])
        self.subject_operations[e['subject_id']] = operation_id
        self.operations[operation_id] = PendingOperation(canon(e), canon(consequence), gl.message.sender_address, 'PENDING', '', '')
        self.history.append(operation_id)
        self.count = u64(int(self.count) + 1)
        return True

    @gl.public.write
    def receive_certificate(self, certificate_json: str) -> None:
        require(gl.message.sender_address == self.resolver, 'only authenticated resolver message')
        require(len(certificate_json.encode('utf-8')) <= 65536, 'certificate size limit')
        certificate = json.loads(certificate_json)
        require(set(certificate) == {'source_contract', 'consumer', 'operation_id', 'relation'}, 'certificate schema')
        require(Address(certificate['source_contract']) == self.resolver and Address(certificate['consumer']) == gl.message.contract_address, 'certificate address binding')
        op = certificate['operation_id']
        require(op in self.operations, 'operation not prepared')
        pending = self.operations[op]
        pd = digest(certificate)
        if pending.acknowledgement:
            require(pending.payload_digest == pd, 'conflicting callback replay')
            gl.get_contract_at(self.resolver).emit(on='finalized').acknowledge(gl.message.contract_address.as_hex, op, pending.acknowledgement)
            return
        relation = certificate['relation']
        e = relation['bindings']
        require(canon(e) == pending.envelope, 'callback request bindings differ')
        require(relation['status'] == 'FINALIZED', 'finality barrier required')
        current = gl.get_contract_at(self.resolver).view().get_relation(e['request_id'])
        # Authenticated message proves delivery finality; view checks current revocation only.
        schema = gl.get_contract_at(self.resolver).view().get_configuration('schema', self.schema_id)
        authorized = gl.get_contract_at(self.resolver).view().is_subject_authorized(e['subject_id'], pending.owner.as_hex)
        valid = authorized and schema['active'] and schema['payload']['kind'] == 'INCIDENT' and current['active'] and current['status'] == 'FINALIZED' and canon(current['bindings']) == canon(e) and canon(current['decision_vector']) == canon(relation['decision_vector'])
        if pending.status == 'RELEASED' or e['generation'] != int(self.generations[e['subject_id']]):
            status = 'STALE'
        elif now_seconds() > e['deadline']:
            status = 'TIMEOUT'
        elif not valid:
            status = 'QUARANTINED'
        elif relation['decision_vector'].get('relation') == 'SAME' and relation['decision_vector'].get('coverage') is True and relation['decision_vector'].get('unresolved') == []:
            status = 'PERMITTED'
        else:
            status = 'REFUSED_UNRESOLVED' if relation['decision_vector'].get('relation') == 'UNKNOWN' else 'REFUSED_DISTINCT'
        if pending.status != 'RELEASED':
            pending.status = status
        self.applied_generations[e['subject_id']] = u64(max(e['generation'], int(self.applied_generations.get(e['subject_id'], u64(0)))))
        pending.payload_digest = pd
        pending.acknowledgement = canon({'operation_id': op, 'payload_digest': pd, 'status': status, 'generation': e['generation']})
        gl.get_contract_at(self.resolver).emit(on='finalized').acknowledge(gl.message.contract_address.as_hex, op, pending.acknowledgement)

    @gl.public.write
    def recover_subject(self, subject_id: str) -> None:
        principal = Address(gl.get_contract_at(self.resolver).view().get_subject_principal(subject_id))
        require(gl.message.sender_address == principal, 'only subject principal may recover')
        operation_id = self.subject_operations.get(subject_id, '')
        require(bool(operation_id), 'no subject operation')
        p = self.operations[operation_id]
        require(p.owner != principal and not gl.get_contract_at(self.resolver).view().is_subject_authorized(subject_id, p.owner.as_hex), 'revoke previous operator before recovery')
        if p.status == 'RELEASED':
            return
        p.status = 'RELEASED'

    @gl.public.view
    def get_acknowledgement(self, operation_id: str) -> str:
        if operation_id not in self.operations:
            return ''
        return self.operations[operation_id].acknowledgement

    @gl.public.view
    def get_operation(self, operation_id: str) -> dict:
        require(operation_id in self.operations, 'unknown operation')
        p = self.operations[operation_id]
        e = json.loads(p.envelope)
        effective = p.status
        if effective == 'PERMITTED':
            current = gl.get_contract_at(self.resolver).view().get_relation(e['request_id'])
            authorized = gl.get_contract_at(self.resolver).view().is_subject_authorized(e['subject_id'], p.owner.as_hex)
            if not authorized or not current['active'] or current['status'] != 'FINALIZED':
                effective = 'QUARANTINED'
        return {'operation_id': operation_id, 'status': p.status, 'effective_status': effective, 'bindings': e, 'consequence': json.loads(p.consequence), 'owner': p.owner.as_hex, 'acknowledgement': p.acknowledgement, 'last_applied_generation': int(self.applied_generations.get(e['subject_id'], u64(0)))}

    @gl.public.view
    def history_page(self, offset: int, limit: int) -> list[str]:
        require(0 <= offset <= int(self.count) and 1 <= limit <= 100, 'pagination bounds')
        return [self.history[i] for i in range(offset, min(offset + limit, int(self.count)))]

    @gl.public.write
    def propose_link(self, operation_id: str, envelope_json: str) -> None:
        e = json.loads(envelope_json)
        consequence = {'action': 'LINK_INCIDENT', 'canonical_id': e['right_subject_id'], 'record_id': e['subject_id'], 'link_owner': gl.message.sender_address.as_hex.lower()}
        self._prepare(operation_id, envelope_json, consequence)

    @gl.public.write
    def release(self, operation_id: str) -> None:
        require(operation_id in self.operations, 'unknown operation')
        p = self.operations[operation_id]
        require(gl.message.sender_address == p.owner, 'only link owner may release')
        p.status = 'RELEASED'

    @gl.public.view
    def resolve_record(self, record_id: str) -> dict:
        op = self.subject_operations.get(record_id, '')
        if not op:
            return {'record_id': record_id, 'canonical_id': record_id, 'status': 'UNLINKED'}
        operation = self.get_operation(op)
        return {'record_id': record_id, 'canonical_id': operation['consequence']['canonical_id'] if operation['effective_status'] == 'PERMITTED' else record_id, 'status': operation['effective_status'], 'operation_id': op}
