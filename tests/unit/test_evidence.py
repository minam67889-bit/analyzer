from __future__ import annotations

from adversarylab.evidence.store import EvidenceStore


def test_record_and_verify(tmp_path, clock):
    store = EvidenceStore(tmp_path, "sess-1", clock=clock)
    store.create_session({"scope": {"domain_roots": ["lab.test"]}}, {"platform": "test"})
    store.record_text("first", kind="log", name="a.txt", sub="logs")
    store.record_text("second", kind="log", name="b.txt", sub="logs")
    ok, problems = store.verify()
    assert ok, problems
    assert len(store.records) == 2


def test_no_overwrite_creates_suffixed_file(tmp_path, clock):
    store = EvidenceStore(tmp_path, "sess-1", clock=clock)
    store.create_session({}, {})
    store.record_text("v1", kind="log", name="x.txt", sub="logs")
    store.record_text("v2", kind="log", name="x.txt", sub="logs")
    paths = [record.path for record in store.records]
    assert len(set(paths)) == 2
    assert "x.txt" in paths[0]
    assert "x-1.txt" in paths[1]


def test_identical_bytes_reuse_path(tmp_path, clock):
    store = EvidenceStore(tmp_path, "sess-1", clock=clock)
    store.create_session({}, {})
    store.record_text("same", kind="log", name="x.txt", sub="logs")
    record = store.record_text("same", kind="log", name="x.txt", sub="logs")
    assert record.path == "logs/x.txt"


def test_finalize_manifest_and_verify(tmp_path, clock):
    store = EvidenceStore(tmp_path, "sess-1", clock=clock)
    store.create_session({}, {})
    store.record_bytes(b"\x00\x01", kind="pcap", name="p.pcap", sub="packets")
    manifest, digest = store.finalize()
    assert manifest.exists()
    assert len(digest) == 64
    ok, problems = store.verify()
    assert ok, problems


def test_tampering_detected(tmp_path, clock):
    store = EvidenceStore(tmp_path, "sess-1", clock=clock)
    store.create_session({}, {})
    store.record_text("original", kind="log", name="a.txt", sub="logs")
    (store.layout.base / "logs" / "a.txt").write_text("tampered")
    ok, problems = store.verify()
    assert not ok
    assert any("hash mismatch" in problem for problem in problems)
