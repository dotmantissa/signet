"""Durable transaction and CLI recovery regressions without network writes."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from eth_account import Account
from eth_utils import keccak
from scripts import studio, signet_cli


def make_session(root, account=None):
    account = account or Account.create()
    signed = account.sign_transaction({'nonce': 0, 'gasPrice': 0, 'gas': 100000, 'to': '0x' + '1' * 40, 'value': 0, 'data': b'fixture', 'chainId': 61999})
    raw = '0x' + signed.raw_transaction.hex()
    outer_hash = '0x' + keccak(signed.raw_transaction).hex()
    provider = SimpleNamespace(make_request=Mock(side_effect=lambda method, params: {'result': outer_hash if method == 'eth_sendRawTransaction' else None}))
    receipt = SimpleNamespace(status=1)
    event = SimpleNamespace(process_receipt=Mock(return_value=[{'args': {'txId': b'consensus-1'}}]))
    eth = SimpleNamespace(get_transaction_receipt=Mock(return_value=receipt), wait_for_transaction_receipt=Mock(return_value=receipt), contract=Mock(return_value=SimpleNamespace(get_event_by_name=Mock(return_value=event))))
    client = SimpleNamespace(provider=provider, w3=SimpleNamespace(eth=eth, to_hex=lambda value: '0x' + value.hex()), chain=SimpleNamespace(consensus_main_contract={'abi': []}), initialize_consensus_smart_contract=Mock())
    def submit(*args, **kwargs):
        client.provider.make_request(method='eth_sendRawTransaction', params=[raw])
        return '0x' + b'consensus-1'.hex()
    client.write_contract = Mock(side_effect=submit)
    client.deploy_contract = Mock(side_effect=submit)
    value = studio.Studio.__new__(studio.Studio)
    value.root, value.client, value.account = root, client, account
    value.network, value.chain_id = 'studionet', 61999
    value.wait = Mock(side_effect=lambda tx, label, **kwargs: {'hash': tx, 'data': {'contract_address': 'deployed'}})
    return value, raw


@pytest.mark.parametrize('field,value', [('sender', '0x' + '2' * 40), ('network', 'other'), ('chain_id', 1)])
@pytest.mark.parametrize('entrypoint', ['queue', 'transaction', 'queue_deploy', 'deploy'])
def test_cached_operation_binds_signer_network_and_chain(tmp_path, field, value, entrypoint):
    s, _ = make_session(tmp_path)
    source = tmp_path / 'source.py'; source.write_text('contract fixture')
    args = ('approve', str(source)) if 'deploy' in entrypoint else ('approve', 'consumer', 'approve_configuration')
    getattr(s, entrypoint)(*args)
    path = tmp_path / 'approve.operation.json'
    op = json.loads(path.read_text()); op[field] = value; path.write_text(json.dumps(op))
    with pytest.raises(ValueError, match='signer/network/chain'):
        getattr(s, entrypoint)(*args)
    assert s.client.write_contract.call_count + s.client.deploy_contract.call_count == 1


def test_reconciliation_attempts_resume_or_issue_a_new_transaction(tmp_path):
    s, _ = make_session(tmp_path)
    s.reconcile('reconcile-op', 'resolver', 'consumer', 'op', 'attempt-1')
    s.reconcile('reconcile-op', 'resolver', 'consumer', 'op', 'attempt-1')
    s.reconcile('reconcile-op', 'resolver', 'consumer', 'op', 'attempt-2')
    assert s.client.write_contract.call_count == 2


def test_cli_exposes_explicit_reconciliation_attempts(tmp_path, monkeypatch):
    session = Mock()
    session.reconcile.return_value = {'result': 'ok'}
    monkeypatch.setattr(signet_cli, 'Studio', Mock(return_value=session))
    monkeypatch.setenv('SIGNET_PRIVATE_KEY', 'unused-in-mocked-client')
    for attempt in ['first', 'first', 'second']:
        monkeypatch.setattr('sys.argv', ['signet', '--journal', str(tmp_path), 'reconcile', 'resolver', 'consumer', 'op', '--attempt-id', attempt])
        signet_cli.main()
    assert [c.args[-1] for c in session.reconcile.call_args_list] == ['first', 'first', 'second']


def test_disk_failure_prevents_any_broadcast(tmp_path, monkeypatch):
    s, _ = make_session(tmp_path)
    actual_atomic_json = studio.atomic_json
    monkeypatch.setattr(studio, 'atomic_json', Mock(side_effect=OSError('interruption before durable preparation')))
    with pytest.raises(OSError):
        s.transaction('evaluate', 'resolver', 'evaluate', ['r1'])
    s.client.provider.make_request.assert_not_called()
    assert not (tmp_path / 'evaluate.operation.json').exists()
    monkeypatch.setattr(studio, 'atomic_json', actual_atomic_json)
    s.transaction('evaluate', 'resolver', 'evaluate', ['r1'])
    assert s.client.provider.make_request.call_count == 1


@pytest.mark.parametrize('deploy', [False, True])
def test_interruption_after_broadcast_reuses_exact_signed_transaction(tmp_path, deploy):
    s, raw = make_session(tmp_path)
    original = s.client.provider.make_request
    def interrupted(method, params):
        original(method, params)
        raise OSError('interruption after broadcast, before consensus ID was saved')
    s.client.provider.make_request = interrupted
    source = tmp_path / 'source.py'; source.write_text('contract fixture')
    invoke = (lambda: s.deploy('op', str(source))) if deploy else (lambda: s.transaction('op', 'resolver', 'evaluate', ['r1']))
    with pytest.raises(OSError): invoke()
    op = json.loads((tmp_path / 'op.operation.json').read_text())
    assert op['phase'] == 'PREPARED'
    assert op['signed_transaction'] == raw
    s.client.provider.make_request = original
    invoke()
    broadcasts = [c.args[1] if c.args else c.kwargs['params'] for c in original.call_args_list if (c.args[0] if c.args else c.kwargs['method']) == 'eth_sendRawTransaction']
    assert broadcasts == [[raw], [raw]]
    assert s.client.write_contract.call_count + s.client.deploy_contract.call_count == 1
    assert json.loads((tmp_path / 'op.operation.json').read_text())['phase'] == 'SUBMITTED'


def test_prepared_transaction_with_existing_receipt_is_not_rebroadcast(tmp_path):
    s, raw = make_session(tmp_path)
    original = s.client.provider.make_request
    s.client.provider.make_request = Mock(side_effect=OSError('before receipt'))
    with pytest.raises(OSError): s.queue('op', 'resolver', 'evaluate', ['r1'])
    s.client.provider.make_request = Mock(return_value={'result': {'status': '0x1'}})
    s.queue('op', 'resolver', 'evaluate', ['r1'])
    assert all(call.args[0] != 'eth_sendRawTransaction' for call in s.client.provider.make_request.call_args_list)
    assert s.client.write_contract.call_count == 1


def test_invalid_prepared_signature_is_rejected(tmp_path):
    s, _ = make_session(tmp_path)
    s.client.provider.make_request = Mock(side_effect=OSError('before receipt'))
    with pytest.raises(OSError): s.queue('op', 'resolver', 'evaluate')
    path = tmp_path / 'op.operation.json'; op = json.loads(path.read_text())
    op['submission_hash'] = '0x' + '0' * 64; path.write_text(json.dumps(op))
    with pytest.raises(ValueError, match='signature/hash'): s.queue('op', 'resolver', 'evaluate')


@pytest.mark.parametrize('label', ['../escape', '.', '..', 'path/name'])
def test_labels_cannot_escape_journal(tmp_path, label):
    s, _ = make_session(tmp_path)
    with pytest.raises(ValueError, match='Invalid journal'): s.queue(label, 'resolver', 'evaluate')


def test_pending_preparation_must_resume_before_signing_another_nonce(tmp_path):
    s, _ = make_session(tmp_path)
    original = s.client.provider.make_request
    s.client.provider.make_request = Mock(side_effect=OSError('interrupted submit'))
    with pytest.raises(OSError): s.queue('first', 'resolver', 'evaluate', ['r1'])
    with pytest.raises(ValueError, match='Resume prepared operation'): s.queue('second', 'resolver', 'evaluate', ['r2'])
    assert s.client.write_contract.call_count == 1
    s.client.provider.make_request = original
    s.queue('first', 'resolver', 'evaluate', ['r1'])
    s.queue('second', 'resolver', 'evaluate', ['r2'])
    assert s.client.write_contract.call_count == 2


def test_studio_transport_uses_bounded_requests_and_propagates_rpc_errors(monkeypatch):
    response = Mock()
    response.json.return_value = {'result': 'ok'}
    post = Mock(return_value=response)
    monkeypatch.setattr(studio.requests, 'post', post)
    provider = SimpleNamespace(url='https://studio.genlayer.com/api', _raise_on_error=Mock())
    studio.studio_transport(provider)
    assert provider.make_request('eth_chainId', []) == {'result': 'ok'}
    assert post.call_args.kwargs['timeout'] == 30
    assert post.call_args.kwargs['headers']['Origin'] == 'https://studio.genlayer.com'
    provider._raise_on_error.side_effect = studio.GenLayerError('Rate limit exceeded')
    with pytest.raises(studio.GenLayerError, match='Rate limit'): provider.make_request('test', [])


@pytest.mark.parametrize('method', ['eth_getTransactionByHash', 'eth_sendRawTransaction'])
def test_transport_timeout_retries_the_identical_request(method, monkeypatch):
    monkeypatch.setattr(studio.time, 'monotonic', lambda: 100)
    monkeypatch.setattr(studio.time, 'sleep', Mock())
    monkeypatch.setattr(studio, '_RPC_LAST', 0)
    provider = SimpleNamespace(make_request=Mock(side_effect=[studio.GenLayerError('Studio transport failed: Read timed out'), {'result': 'ok'}]))
    original = provider.make_request
    studio.paced_provider(provider)
    assert provider.make_request(method, ['same-signed-bytes-or-hash']) == {'result': 'ok'}
    assert original.call_args_list[0] == original.call_args_list[1]
