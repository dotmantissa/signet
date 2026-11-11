"""Studio transaction journal. A receipt is successful only with successful execution."""
import json
import time
import os
import re
import fcntl
from contextlib import contextmanager
from eth_utils import keccak
from web3.logs import DISCARD
from pathlib import Path
from eth_account import Account
from genlayer_py.client import GenLayerClient
from copy import deepcopy
import requests
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus
from gltest.assertions import tx_execution_succeeded
from genlayer_py.exceptions import GenLayerError

_RPC_LAST = 0.0


def studio_transport(provider):
    def request(method, params):
        try:
            response = requests.post(provider.url, json={'jsonrpc': '2.0', 'id': time.time_ns() // 1000000, 'method': method, 'params': params}, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (compatible; Signet/1.0)', 'Origin': 'https://studio.genlayer.com'}, timeout=30)
            response.raise_for_status()
            result = response.json()
        except (requests.RequestException, ValueError) as error:
            raise GenLayerError('Studio transport failed: ' + str(error)) from error
        provider._raise_on_error(result, method)
        return result
    provider.make_request = request


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
                message = str(error).lower()
                rate_limited = any(code in message for code in ['rate limit', '429', 'code=-32029', 'code=-32429'])
                transient = any(code in message for code in ['timed out', 'connection aborted', 'connection reset', '502', '503', '504'])
                if retry == 3 or not (rate_limited or transient):
                    raise
                delay = 45 if rate_limited else min(3 * (2 ** retry), 12)
                print('Studio RPC retry; reusing identical request after', delay, 'seconds', flush=True)
                time.sleep(delay)
        raise RuntimeError("unreachable")
    provider.make_request = request



def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as stream:
        stream.write(json.dumps(value, indent=2, default=str) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Studio:
    def __init__(self, private_key, evidence_dir='evidence/studio'):
        self.account = Account.from_key(private_key)
        self.client = GenLayerClient(deepcopy(studionet), account=self.account)
        studio_transport(self.client.provider)
        paced_provider(self.client.provider)
        self.network = 'studionet'
        self.chain_id = studionet.id
        if int(self.client.provider.make_request('eth_chainId', [])['result'], 16) != self.chain_id:
            raise ValueError('Studio RPC chain differs from configured chain')
        self.client.initialize_consensus_smart_contract()
        self.root = Path(evidence_dir)
        self.root.mkdir(parents=True, exist_ok=True)

    def wait(self, tx, label, seconds=600, require_success=True):
        self._operation_path(label)
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

    @contextmanager
    def _journal_lock(self):
        self.root.mkdir(parents=True, exist_ok=True)
        with (self.root / '.journal.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _operation_path(self, label):
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,160}', label) or label in ['.', '..']:
            raise ValueError('Invalid journal operation label')
        return self.root / (label + '.operation.json')

    def _binding(self):
        return {'network': self.network, 'chain_id': self.chain_id, 'sender': self.account.address, 'rpc': getattr(self.client.provider, 'url', 'https://studio.genlayer.com/api')}

    def _check_binding(self, operation):
        expected = self._binding()
        if operation.get('rpc', expected['rpc']) != expected['rpc']:
            raise ValueError('Journal RPC endpoint differs from this session')
        if operation.get('network') != expected['network'] or operation.get('chain_id') != expected['chain_id'] or operation.get('sender', '').lower() != expected['sender'].lower():
            raise ValueError('Journal signer/network/chain differs from this session')

    def _resume_prepared(self, operation):
        raw = operation.get('signed_transaction')
        if not raw:
            raise ValueError('Journal lacks prepared transaction identity; cannot safely resubmit')
        raw_bytes = bytes.fromhex(raw.removeprefix('0x'))
        outer_hash = '0x' + keccak(raw_bytes).hex()
        if outer_hash != operation.get('submission_hash') or Account.recover_transaction(raw).lower() != self.account.address.lower():
            raise ValueError('Prepared transaction signature/hash differs from journal')
        # If an earlier broadcast succeeded, recover its receipt without another send.
        receipt = self.client.w3.eth.get_transaction_receipt(outer_hash) if self._has_submission(outer_hash) else None
        if receipt is None:
            try:
                response = self.client.provider.make_request('eth_sendRawTransaction', [raw])
                if response['result'].lower() != outer_hash.lower():
                    raise ValueError('RPC returned an unexpected signed transaction hash')
            except GenLayerError as error:
                if not any(reason in str(error).lower() for reason in ['already known', 'nonce too low']):
                    raise
            receipt = self.client.w3.eth.wait_for_transaction_receipt(outer_hash)
        if receipt.status != 1:
            raise RuntimeError('Prepared transaction execution failed')
        self.client.initialize_consensus_smart_contract()
        contract = self.client.w3.eth.contract(abi=self.client.chain.consensus_main_contract['abi'])
        events = contract.get_event_by_name('NewTransaction').process_receipt(receipt, DISCARD)
        if not events:
            raise RuntimeError('Prepared transaction emitted no consensus transaction')
        return self.client.w3.to_hex(events[0]['args']['txId'])

    def _has_submission(self, transaction_hash):
        # This read distinguishes an absent receipt from actual RPC failures.
        response = self.client.provider.make_request('eth_getTransactionReceipt', [transaction_hash])
        return response.get('result') is not None

    def _queue_operation(self, label, intent, submit):
        path = self._operation_path(label)
        with self._journal_lock():
            if path.exists():
                operation = json.loads(path.read_text())
                self._check_binding(operation)
                if any(operation.get(k) != value for k, value in intent.items()):
                    raise ValueError('Conflicting journal operation: ' + label)
                if operation.get('transaction_hash'):
                    return operation['transaction_hash']
                tx = self._resume_prepared(operation)
            else:
                for other_path in self.root.glob('*.operation.json'):
                    other = json.loads(other_path.read_text())
                    if other.get('phase') == 'PREPARED' and not other.get('transaction_hash') and other.get('sender', '').lower() == self.account.address.lower():
                        raise ValueError('Resume prepared operation before another nonce is signed: ' + other_path.name)
                operation = dict(self._binding(), **intent)
                provider = self.client.provider
                original = provider.make_request
                def journal_before_broadcast(method, params):
                    if method == 'eth_sendRawTransaction':
                        raw = params[0]
                        outer_hash = '0x' + keccak(bytes.fromhex(raw.removeprefix('0x'))).hex()
                        operation.update({'signed_transaction': raw, 'submission_hash': outer_hash, 'phase': 'PREPARED'})
                        # SDK has already signed but has not yet submitted anything.
                        atomic_json(path, operation)
                    return original(method, params)
                provider.make_request = journal_before_broadcast
                try:
                    tx = submit()
                finally:
                    provider.make_request = original
                if not operation.get('signed_transaction'):
                    raise RuntimeError('SDK bypassed the durable broadcast barrier')
            operation.update({'transaction_hash': tx, 'phase': 'SUBMITTED'})
            atomic_json(path, operation)
            print(label, 'SUBMITTED', tx, flush=True)
            return tx

    def queue(self, label, address, method, args=None):
        args = args or []
        return self._queue_operation(label, {'address': address, 'method': method, 'args': args}, lambda: self.client.write_contract(address, method, args=args))

    def finish_batch(self, operations, seconds=600):
        pending = list(operations)
        results = {}
        end = time.monotonic() + seconds
        while pending and time.monotonic() < end:
            next_pending = []
            for label, tx in pending:
                self._operation_path(label)
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
            pending=next_pending
            if pending: time.sleep(15)
        if pending: raise TimeoutError('Journaled pending operations: '+str(pending))
        return results

    def transaction(self, label, address, method, args=None, require_success=True):
        return self.wait(self.queue(label, address, method, args), label, require_success=require_success)

    def reconcile(self, label, address, consumer, operation_id, attempt_id):
        # Explicit attempt IDs distinguish a new reconciliation from resuming one.
        self._operation_path(attempt_id)
        return self.transaction(label + '-' + attempt_id, address, 'reconcile_delivery', [consumer, operation_id])

    def queue_deploy(self, label, path, args=None):
        import hashlib
        args = args or []
        code = Path(path).read_text()
        intent = {'source_file': str(path), 'code_sha256': hashlib.sha256(code.encode()).hexdigest(), 'args': args}
        return self._queue_operation(label, intent, lambda: self.client.deploy_contract(code, args=args))

    def deploy(self, label, path, args=None):
        return self.wait(self.queue_deploy(label, path, args), label)['data']['contract_address']

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
