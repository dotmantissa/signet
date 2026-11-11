"""RPC rejection and receipt recovery checks; no network or signing keys."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from genlayer_py.exceptions import GenLayerError
from scripts import studio


def session(tmp_path, client):
    value = studio.Studio.__new__(studio.Studio)
    value.root = tmp_path
    value.client = client
    return value


def test_rate_rejection_retries_without_retrying_other_errors(monkeypatch):
    monkeypatch.setattr(studio.time, 'monotonic', lambda: 100)
    sleep = Mock()
    monkeypatch.setattr(studio.time, 'sleep', sleep)
    monkeypatch.setattr(studio, '_RPC_LAST', 0)
    provider = SimpleNamespace(make_request=Mock(side_effect=[GenLayerError('Rate limit exceeded'), {'result': 'ok'}]))
    original = provider.make_request
    studio.paced_provider(provider)
    assert provider.make_request('eth_sendRawTransaction', ['same-encoded-payload']) == {'result': 'ok'}
    assert original.call_count == 2
    assert original.call_args_list[0] == original.call_args_list[1]
    assert any(call.args == (45,) for call in sleep.call_args_list)
    provider = SimpleNamespace(make_request=Mock(side_effect=GenLayerError('execution error')))
    original = provider.make_request
    studio.paced_provider(provider)
    with pytest.raises(GenLayerError, match='execution error'):
        provider.make_request('test', [])
    assert original.call_count == 1


def test_finalized_receipt_cache_checks_execution_without_rpc(tmp_path, monkeypatch):
    receipt = {'hash': 'tx1', 'status': 7}
    (tmp_path / 'operation.receipt.json').write_text(json.dumps(receipt))
    client = SimpleNamespace(get_transaction=Mock(side_effect=AssertionError('unexpected RPC')))
    monkeypatch.setattr(studio, 'tx_execution_succeeded', lambda _: True)
    assert session(tmp_path, client).wait('tx1', 'operation') == receipt
    monkeypatch.setattr(studio, 'tx_execution_succeeded', lambda _: False)
    with pytest.raises(RuntimeError, match='execution failed'):
        session(tmp_path, client).wait('tx1', 'operation')


def test_cached_receipt_cannot_answer_for_another_transaction(tmp_path):
    (tmp_path / 'operation.receipt.json').write_text(json.dumps({'hash': 'tx1', 'status': 7}))
    client = SimpleNamespace(get_transaction=Mock(side_effect=AssertionError('unexpected RPC')))
    with pytest.raises(ValueError, match='another transaction'):
        session(tmp_path, client).wait('tx2', 'operation')


def test_batch_polls_beyond_a_cached_pending_receipt(tmp_path, monkeypatch):
    (tmp_path / 'operation.receipt.json').write_text(json.dumps({'hash': 'tx1', 'status': 1}))
    finalized = {'hash': 'tx1', 'status': 7}
    client = SimpleNamespace(get_transaction=Mock(return_value=finalized))
    monkeypatch.setattr(studio, 'tx_execution_succeeded', lambda _: True)
    monkeypatch.setattr(studio.time, 'sleep', lambda _: None)
    result = session(tmp_path, client).finish_batch([('operation', 'tx1')])
    assert result == {'operation': finalized}
    client.get_transaction.assert_called_once_with('tx1')
