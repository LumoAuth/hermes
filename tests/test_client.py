"""The LumoAuth client against the local mock: assertion, DPoP, nonce, receipts, approvals, usage."""

from __future__ import annotations

import pytest

from helpers import set_up_guard
from lumoauth_hermes.client import AgentClient, AuthError, NetworkError
from lumoauth_hermes.runtime import ReceiptQueue, iso, send_receipts, valid_receipt
from mock_lumoauth import MockLumoAuth


@pytest.fixture
def mock():
    server = MockLumoAuth().start()
    yield server
    server.stop()


def _client(tmp_path, mock, **config):
    s = set_up_guard(tmp_path, mock, **config)
    cfg = s.home.read_config()
    return AgentClient(cfg, s.key), s


def _receipt(i: int = 0) -> dict:
    return {"tool": "read_file", "decision": "allowed", "outcome": "succeeded", "duration_ms": i,
            "arguments_sha256": "0" * 64, "occurred_at": iso()}


def test_token_uses_private_key_jwt_and_dpop(tmp_path, mock):
    client, _ = _client(tmp_path, mock)
    me = client.me()
    assert me["identity"]["status"] == "active"
    assert mock.state.errors == []
    assert mock.state.token_requests == 1
    client.me()
    assert mock.state.token_requests == 1, "the token is cached"
    assert client.sender_constrained is True


def test_dpop_nonce_is_retried_once(tmp_path, mock):
    mock.state.require_nonce = True
    client, _ = _client(tmp_path, mock)
    client.me()
    assert mock.state.token_requests == 2
    assert mock.state.errors == []


def test_invalid_client_is_an_auth_error(tmp_path, mock):
    mock.state.token_error = "invalid_client"
    client, _ = _client(tmp_path, mock)
    with pytest.raises(AuthError):
        client.me()


def test_me_403_is_an_auth_error(tmp_path, mock):
    mock.state.me_status_code = 403
    client, _ = _client(tmp_path, mock)
    with pytest.raises(AuthError):
        client.me()


def test_unreachable_server_is_a_network_error(tmp_path, mock):
    client, s = _client(tmp_path, mock)
    mock.stop()
    with pytest.raises(NetworkError):
        client.me(timeout=2)


def test_wrong_key_is_refused(tmp_path, mock):
    client, s = _client(tmp_path, mock)
    mock.state.jwks.clear()
    with pytest.raises(AuthError):
        client.token()


def test_receipts_are_batched_by_fifty(tmp_path, mock):
    client, _ = _client(tmp_path, mock)
    queue = ReceiptQueue()
    for i in range(60):
        queue.add(_receipt(i))
    while len(queue):
        assert send_receipts(client, queue) is None
    assert mock.state.receipt_batches == [50, 10]
    assert len(mock.state.receipts) == 60
    assert mock.state.errors == []


def test_receipts_429_and_5xx_are_kept_and_retried(tmp_path, mock):
    client, _ = _client(tmp_path, mock)
    mock.state.receipt_responses.extend([429, 503])
    queue = ReceiptQueue()
    queue.add(_receipt())
    assert send_receipts(client, queue) == 1.0  # Retry-After
    assert len(queue) == 1
    assert send_receipts(client, queue) is not None
    assert len(queue) == 1
    assert send_receipts(client, queue) is None
    assert len(mock.state.receipts) == 1


def test_receipts_400_drops_the_batch(tmp_path, mock, monkeypatch):
    client, _ = _client(tmp_path, mock)
    queue = ReceiptQueue()
    queue.add(_receipt())
    monkeypatch.setattr("lumoauth_hermes.runtime.valid_receipt", lambda r, now=None: True)
    queue.add({"tool": "x", "decision": "allowed", "arguments": {"secret": 1}})  # unknown field -> 400
    assert send_receipts(client, queue) is None
    assert len(queue) == 0
    assert queue.rejected == 2
    assert mock.state.receipts == []


def test_invalid_receipts_never_reach_the_server(tmp_path, mock):
    client, _ = _client(tmp_path, mock)
    queue = ReceiptQueue()
    queue.add(_receipt())
    queue.add({"tool": "x", "decision": "denied", "outcome": "succeeded"})
    queue.add({"tool": "x", "decision": "allowed", "occurred_at": "2020-01-01T00:00:00.000Z"})
    assert send_receipts(client, queue) is None
    assert len(mock.state.receipts) == 1
    assert queue.rejected == 2


def test_queue_is_bounded_and_counts_drops():
    queue = ReceiptQueue(limit=3)
    for i in range(5):
        queue.add(_receipt(i))
    assert len(queue) == 3
    assert queue.dropped == 2


def test_valid_receipt_matches_server_rules():
    assert valid_receipt(_receipt())
    assert not valid_receipt({**_receipt(), "server_id": "bad server"})
    assert not valid_receipt({**_receipt(), "error_code": "has spaces"})
    assert not valid_receipt({**_receipt(), "audit_id": "xyz"})


def test_usage_and_ask(tmp_path, mock):
    client, _ = _client(tmp_path, mock)
    assert client.report_usage(1530).status_code == 200
    assert mock.state.usage == [1530]
    answer = client.ask("files:read", {"tool": "read_file", "server": None, "host": "hermes"})
    assert answer["allowed"] is True
    assert mock.state.asks[0] == {"action": "files:read", "context": {"tool": "read_file", "server": None,
                                                                      "host": "hermes"}, "audit": "always"}


def test_approval_create_and_poll(tmp_path, mock):
    client, _ = _client(tmp_path, mock)
    response = client.request_approval({"task_id": "hermes-1", "reason": "x", "impact": "low",
                                        "on_behalf_of": "u", "meta": {}})
    assert response.status_code == 201
    token = response.json()["approval_token"]
    mock.state.approval_statuses.extend(["pending", "approved"])
    assert client.approval_status(token).json()["status"] == "pending"
    assert client.approval_status(token).json()["status"] == "approved"
    assert mock.state.errors == []


def test_bearer_token_is_reported(tmp_path, mock):
    mock.state.token_type = "Bearer"
    client, _ = _client(tmp_path, mock)
    client.me()
    assert client.sender_constrained is False
