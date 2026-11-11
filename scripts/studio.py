"""Studio transaction journal. A receipt is successful only with successful execution."""
import json
import time
from pathlib import Path
from eth_account import Account
from genlayer_py import create_client
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus
from gltest.assertions import tx_execution_succeeded
from genlayer_py.exceptions import GenLayerError

_RPC_LAST = 0.0


def paced_provider(provider):
    original = provider.make_request
    def request(method, params):
        global _RPC_LAST
        for retry in range(4):
            remaining = 3.0 - (time.monotonic() - _RPC_LAST)
            if remaining > 0: time.sleep(remaining)
            _RPC_LAST = time.monotonic()
            try:
                return original(method, params)
            except GenLayerError as error:
                if "Rate limit" not in str(error) or retry == 3: raise
                print("Studio RPC rate window; pausing 45 seconds", flush=True)
                time.sleep(45)
        raise RuntimeError("unreachable")
    provider.make_request = request



def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, default=str) + '\n')
    temporary.replace(path)


class Studio:
    def __init__(self, private_key, evidence_dir='evidence/studio'):
        self.account = Account.from_key(private_key)
        self.client = create_client(chain=studionet, account=self.account)
        paced_provider(self.client.provider)
        self.root = Path(evidence_dir)
        self.root.mkdir(parents=True, exist_ok=True)

    def wait(self, tx, label, seconds=600, require_success=True):
        cached_path = self.root / (label + '.receipt.json')
        if cached_path.exists():
            cached = json.loads(cached_path.read_text())
            if cached.get('hash') != tx:
                raise ValueError(label + ': cached receipt belongs to another transaction')
            if str(cached.get('status')) in ['7', 'FINALIZED', 'TransactionStatus.FINALIZED']:
                if require_success and not tx_execution_succeeded(cached):
                    raise RuntimeError(label + ': cached finalized execution failed')
                return cached
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            result = self.client.get_transaction(tx)
            # Studio SDK represents FINALIZED as integer 7.
            if str(result.get('status')) in ['7', 'FINALIZED', 'TransactionStatus.FINALIZED']:
                atomic_json(self.root / (label + '.receipt.json'), result)
                success = tx_execution_succeeded(result)
                print(label, 'FINALIZED', 'SUCCESS' if success else 'EXECUTION_ERROR', flush=True)
                if require_success and not success:
                    leader = result.get('consensus_data', {}).get('leader_receipt', [{}])[0]
                    raise RuntimeError(label + ': ' + json.dumps(leader.get('genvm_result', leader), default=str)[:4000])
                return result
            time.sleep(5)
        raise TimeoutError('Journaled operation remains pending: ' + label + ' ' + str(tx))

    def queue(self, label, address, method, args=None):
        operation_path = self.root / (label + '.operation.json')
        args = args or []
        if operation_path.exists():
            operation = json.loads(operation_path.read_text())
            if operation['address'] != address or operation['method'] != method or operation['args'] != args:
                raise ValueError('Conflicting journal operation: ' + label)
            return operation['transaction_hash']
        tx = self.client.write_contract(address, method, args=args)
        atomic_json(operation_path, {'network':'studionet','chain_id':61999,'sender':self.account.address,'address':address,'method':method,'args':args,'transaction_hash':tx})
        print(label, 'SUBMITTED', tx, flush=True)
        time.sleep(8)
        return tx

    def finish_batch(self, operations, seconds=600):
        pending = list(operations)
        results = {}
        end = time.monotonic() + seconds
        while pending and time.monotonic() < end:
            next_pending = []
            for label, tx in pending:
                path = self.root / (label + '.receipt.json')
                result = json.loads(path.read_text()) if path.exists() else None
                if result is not None and result.get('hash') != tx:
                    raise ValueError(label + ': cached receipt belongs to another transaction')
                if result is None or str(result.get('status')) not in ['7', 'FINALIZED', 'TransactionStatus.FINALIZED']:
                    result = self.client.get_transaction(tx)
                if str(result.get('status')) in ['7', 'FINALIZED', 'TransactionStatus.FINALIZED']:
                    atomic_json(path,result)
                    if not tx_execution_succeeded(result):
                        raise RuntimeError(label + ' finalized with execution error: ' + json.dumps(result.get('consensus_data',{}).get('leader_receipt',[{}])[0].get('genvm_result',{}),default=str)[:3000])
                    results[label] = result
                    print(label, 'FINALIZED SUCCESS', flush=True)
                else:
                    next_pending.append((label,tx))
                time.sleep(1)
            pending=next_pending
            if pending: time.sleep(15)
        if pending: raise TimeoutError('Journaled pending operations: '+str(pending))
        return results

    def transaction(self, label, address, method, args=None, require_success=True):
        operation_path = self.root / (label + '.operation.json')
        args = args or []
        if operation_path.exists():
            operation = json.loads(operation_path.read_text())
            if operation['address'] != address or operation['method'] != method or operation['args'] != args:
                raise ValueError('Conflicting journal operation: ' + label)
            tx = operation['transaction_hash']
        else:
            tx = self.client.write_contract(address, method, args=args)
            atomic_json(operation_path, {'network':'studionet','chain_id':61999,'sender':self.account.address,'address':address,'method':method,'args':args,'transaction_hash':tx})
            print(label, 'SUBMITTED', tx, flush=True)
        return self.wait(tx,label,require_success=require_success)

    def queue_deploy(self, label, path, args=None):
        import hashlib
        args = args or []
        code = Path(path).read_text()
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        operation_path = self.root / (label + '.operation.json')
        if operation_path.exists():
            operation=json.loads(operation_path.read_text())
            if operation['code_sha256'] != code_hash or operation['args'] != args:
                raise ValueError('Deployment source differs from journal: '+label)
            return operation['transaction_hash']
        tx=self.client.deploy_contract(code,args=args)
        atomic_json(operation_path,{'network':'studionet','chain_id':61999,'sender':self.account.address,'source_file':str(path),'code_sha256':code_hash,'args':args,'transaction_hash':tx})
        print(label,'SUBMITTED',tx,flush=True)
        time.sleep(8)
        return tx

    def deploy(self, label, path, args=None):
        operation_path = self.root / (label + '.operation.json')
        code = Path(path).read_text()
        import hashlib
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        args = args or []
        if operation_path.exists():
            operation = json.loads(operation_path.read_text())
            if operation['code_sha256'] != code_hash or operation['args'] != args:
                raise ValueError('Deployment source differs from journal: ' + label)
            tx = operation['transaction_hash']
        else:
            tx = self.client.deploy_contract(code, args=args)
            atomic_json(operation_path, {'network':'studionet','chain_id':61999,'sender':self.account.address,'source_file':str(path),'code_sha256':code_hash,'args':args,'transaction_hash':tx})
            print(label,'SUBMITTED',tx,flush=True)
        receipt = self.wait(tx,label)
        return receipt['data']['contract_address']

    def read(self, address, method, args=None):
        return self.client.read_contract(address,method,args=args or [])

    def wait_relation(self, resolver, request_id, seconds=600):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            result = self.read(resolver,'get_relation',[request_id])
            if result['status'] in ['FINALIZED','UNRESOLVED','TIMEOUT','QUARANTINED','SUPERSEDED']:
                atomic_json(self.root / (request_id + '.relation.json'), result)
                print(request_id,'RELATION',result['status'],result['decision_vector'].get('relation'),flush=True)
                return result
            time.sleep(8)
        raise TimeoutError('Assessment message did not reach a terminal application state: '+request_id)

    def wait_delivery(self, resolver, consumer, operation_id, seconds=600):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            result = self.read(resolver,'get_delivery',[consumer,operation_id])
            if result['status'] == 'ACKNOWLEDGED':
                atomic_json(self.root / (operation_id + '.delivery.json'), result)
                print(operation_id,'DELIVERY_ACKNOWLEDGED',flush=True)
                return result
            time.sleep(8)
        raise TimeoutError('Delivery still pending; reconcile by operation ID: '+operation_id)
