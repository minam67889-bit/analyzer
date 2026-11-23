from __future__ import annotations

import pytest

from adversarylab.protocols import http


def test_parse_request():
    raw = b"GET /a?b=c HTTP/1.1\r\nHost: x.lab.test\r\nUser-Agent: agent\r\nContent-Length: 3\r\n\r\nabc"
    request = http.parse_request(raw)
    assert request.method == "GET"
    assert request.target == "/a?b=c"
    assert request.version == "HTTP/1.1"
    assert request.headers["host"] == "x.lab.test"
    assert request.body_length == 3
    assert http.host_from_request(request) == "x.lab.test"


def test_parse_response():
    raw = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nnope"
    response = http.parse_response(raw)
    assert response.status == 404
    assert response.reason == "Not Found"


def test_malformed_rejected():
    with pytest.raises(http.HttpError):
        http.parse_request(b"NOTHTTP\r\n\r\n")
