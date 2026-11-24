"""API tests. The default tests run on the SYNTHETIC fixture (tests/synthetic_api_fixture.py); the `realdata` tests (one
per route) run against the real results and are deselected by default (`pytest -m realdata`)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import synthetic_api_fixture as fx
from api.app import create_app
from api.config import ApiConfig
from api.provenance import read_git_head


@pytest.fixture(scope="module")
def client(tmp_path_factory) -> TestClient:
    cfg = fx.build(tmp_path_factory.mktemp("api"))
    return TestClient(create_app(cfg))


def check_provenance(body: dict, synthetic: bool) -> None:
    p = body["provenance"]
    assert set(p) == {"data_source", "synthetic", "results_code_commit", "served_by_commit", "results_files",
                      "generated_at", "source_files"}
    assert p["synthetic"] is synthetic
    assert p["data_source"] == ("SYNTHETIC_TEST_FIXTURE" if synthetic else "lab_captures")
    assert isinstance(p["source_files"], list) and p["source_files"]


# ---------------------------------------------------------------------------------------------- SYNTHETIC fixture tests
def test_meta(client):
    r = client.get("/api/meta")
    assert r.status_code == 200
    b = r.json()
    check_provenance(b, True)
    assert b["version"] == "0.1.0" and set(b["detectors"]) == {"rf", "ae", "iforest"}
    assert fx.P0 in b["profiles"] and fx.P1 in b["profiles"]
    assert "naive" in b["methods"]["baseline"] and "canon_bs_k120_true" in b["methods"]["canon"]
    text = " ".join(b["caveats"]).lower()
    for word in ("single machine", "local network", "scripted", "cipher suite"):
        assert word in text


def test_ladder_model_vs_observed(client):
    r = client.get("/api/ladder", params={"kem": "mlkem768", "auth": "mldsa65", "chain": "leaf_int"})
    assert r.status_code == 200
    b = r.json()
    check_provenance(b, True)
    from pqdl.canon import context_profile
    from pqdl.handshake import client_flight_bytes, server_flight_bytes
    prof = context_profile(fx.P1)
    assert b["mss"] == 1448 and b["model"]["B_S"] == server_flight_bytes(prof) and b["model"]["B_C"] == client_flight_bytes(prof)
    steps = [s["step"] for s in b["model"]["ladder"]]
    assert steps[0] == "ClientHello" and steps[-1] == "client Finished"
    s2c = b["comparison"]["server_to_client_bytes"]
    assert s2c["observed"] == pytest.approx(b["observed"]["hs_s2c_bytes_median"])
    assert s2c["difference"] == pytest.approx(s2c["observed"] - s2c["model"])
    assert 15976 <= b["observed"]["hs_s2c_bytes_median"] <= 15978               # SYNTHETIC hs bytes


def test_ladder_errors(client):
    assert client.get("/api/ladder", params={"kem": "nope", "auth": "x", "chain": "leaf"}).status_code == 404
    assert client.get("/api/ladder", params={"kem": "X25519"}).status_code == 422
    # valid profile name but absent from the fixture flows
    assert client.get("/api/ladder", params={"kem": "X25519MLKEM768", "auth": "mldsa87", "chain": "leaf"}).status_code == 404


def test_drift_filters(client):
    b = client.get("/api/drift").json()
    check_provenance(b, True)
    assert b["n_rows"] == 3
    b = client.get("/api/drift", params={"view": "hs"}).json()
    assert [r["feature"] for r in b["rows"]] == ["hs_s2c_bytes"] and b["rows"][0]["noise95_eta2"] == 0.01
    b = client.get("/api/drift", params={"workload": "slow_send", "view": "flow"}).json()
    assert len(b["rows"]) == 1 and b["rows"][0]["psi"] == 2.0 and b["rows"][0]["noise95_max_psi"] == 0.2
    assert client.get("/api/drift", params={"view": "bogus"}).status_code == 422
    assert client.get("/api/drift", params={"workload": "nonexistent"}).json()["rows"] == []


def test_detectors_filters_cis_and_pcap_level(client):
    b = client.get("/api/detectors", params={"detector": "rf", "method": "naive", "profile": fx.P1}).json()
    check_provenance(b, True)
    assert b["n_records"] == 1
    rec = b["records"][0]
    fpr = rec["metrics"]["fpr"]
    assert fpr["value"] == 0.90 and fpr["ci_lo"] == pytest.approx(0.89) and fpr["ci_hi"] == pytest.approx(0.91)
    assert {"fpr", "tpr_all", "auroc"} <= set(rec["metrics"])
    assert rec["pcap_level"]["mean_fpr"] == 0.88 and rec["pcap_level"]["sd_across_pcaps"] == 0.02
    other = client.get("/api/detectors", params={"detector": "ae", "method": "naive", "profile": fx.P1}).json()["records"][0]
    assert other["pcap_level"] is None                                            # only where it exists
    allr = client.get("/api/detectors", params={"profile": fx.P1}).json()
    assert allr["n_records"] == 3 * 7                                              # 3 detectors x 7 methods
    assert client.get("/api/detectors", params={"detector": "svm"}).status_code == 422


def test_pqmix_formula_is_the_weighted_average_of_measured_fprs(client):
    b = client.get("/api/pqmix", params={"pi": 0.25, "detector": "rf", "profile": fx.P1}).json()
    check_provenance(b, True)
    assert b["simulation"] is False and "pi * FPR_profile" in b["formula"]
    naive = b["methods"]["naive"]
    assert naive["fpr_mix"] == pytest.approx(0.25 * 0.90 + 0.75 * 0.02)
    assert b["methods"]["CANON-B split k=120"]["fpr_mix"] == pytest.approx(0.25 * 0.05 + 0.75 * 0.02)
    assert b["methods"]["V_APP"]["fpr_mix"] == pytest.approx(0.25 * 0.03 + 0.75 * 0.02)
    ends = [client.get("/api/pqmix", params={"pi": p, "detector": "ae", "profile": fx.P1}).json()["methods"]["naive"]["fpr_mix"] for p in (0, 1)]
    assert ends == [pytest.approx(0.02), pytest.approx(0.90)]
    assert client.get("/api/pqmix", params={"pi": 1.5, "detector": "rf", "profile": fx.P1}).status_code == 422
    assert client.get("/api/pqmix", params={"pi": 0.5, "detector": "rf", "profile": "nope"}).status_code == 404


def collect(ws) -> list[dict]:
    msgs = []
    while True:
        m = ws.receive_json()
        msgs.append(m)
        if m["type"] == "done":
            return msgs


@pytest.mark.parametrize("method", ["naive", "naive_app", "canon_a", "canon_b"])
def test_stream_replays_recorded_flows(client, method):
    with client.websocket_connect(f"/api/stream?detector=rf&method={method}&profile={fx.P1}&speed=5000&limit=60") as ws:
        msgs = collect(ws)
    hello, flows, done = msgs[0], msgs[1:-1], msgs[-1]
    assert hello["type"] == "hello" and hello["replay"] is True and "REPLAY" in hello["notice"] and "not live" in hello["notice"]
    check_provenance(hello, True)
    assert len(flows) == 60 == done["n_flows"] and all(f["replay"] for f in flows)
    offsets = [f["recorded_offset_s"] for f in flows]
    assert offsets == sorted(offsets)                                              # recorded time order
    assert all(set(f) >= {"score", "threshold", "alert", "workload", "label"} for f in flows)
    assert done["alerts"] == sum(f["alert"] for f in flows)


def test_stream_naive_flags_shifted_profile_and_canon_b_does_not(client):
    def alerts(method):
        with client.websocket_connect(f"/api/stream?detector=rf&method={method}&profile={fx.P1}&speed=5000&limit=700") as ws:
            msgs = collect(ws)
        benign = [m for m in msgs if m["type"] == "flow" and m["label"] == "benign"]
        return sum(m["alert"] for m in benign) / len(benign)
    assert alerts("naive") > 0.5 and alerts("canon_b") < 0.25                      # SYNTHETIC shift planted in the bytes columns


def test_stream_rejects_bad_parameters(client):
    for q in ("detector=svm&method=naive", "detector=rf&method=oracle", "detector=rf&method=naive&speed=0",
              f"detector=rf&method=naive&profile=unknown"):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/api/stream?{q}") as ws:
                ws.receive_json()


def test_read_only_methods_and_no_files_written(client, tmp_path_factory):
    for verb in ("post", "put", "delete", "patch"):
        assert getattr(client, verb)("/api/meta").status_code == 405
    import api.app
    root = Path(api.app.__file__).parent                                                              # the api package dir
    before = sorted(p.name for p in root.iterdir() if p.is_file())
    for url in ("/api/meta", "/api/drift", "/api/detectors", "/api/pqmix?pi=0.5&detector=rf&profile=" + fx.P1):
        client.get(url)
    assert sorted(p.name for p in root.iterdir() if p.is_file()) == before


def test_cors_only_allows_the_dev_origin(client):
    ok = client.get("/api/meta", headers={"Origin": "http://localhost:5173"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.get("/api/meta", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in bad.headers


def test_missing_results_gives_503_with_provenance(tmp_path):
    cfg = fx.build(tmp_path)
    (cfg.results_dir / "lab_drift.csv").unlink()
    r = TestClient(create_app(cfg)).get("/api/drift")
    assert r.status_code == 503 and r.json()["provenance"]["synthetic"] is True


def test_git_head_reader(tmp_path):
    assert read_git_head(tmp_path) == "unknown"
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "refs" / "heads" / "main").write_text("abc123\n")
    assert read_git_head(tmp_path) == "abc123"
    (git / "HEAD").write_text("deadbeef\n")
    assert read_git_head(tmp_path) == "deadbeef"


def test_default_config_binds_localhost_and_real_provenance():
    cfg = ApiConfig()
    assert cfg.host == "127.0.0.1" and cfg.synthetic is False and cfg.allowed_origin == "http://localhost:5173"


# ---------------------------------------------------------------------------------------------- real-data tests
@pytest.fixture(scope="module")
def real() -> TestClient:
    return TestClient(create_app(ApiConfig(eager_train=False)))


@pytest.mark.realdata
def test_real_meta(real):
    b = real.get("/api/meta").json()
    check_provenance(b, False)
    assert len(b["profiles"]) == 18 and b["provenance"]["served_by_commit"] != "unknown"
    assert isinstance(b["provenance"]["results_code_commit"], str) and b["served_by_commit"] == b["provenance"]["served_by_commit"]


@pytest.mark.realdata
def test_real_ladder(real):
    b = real.get("/api/ladder", params={"kem": "X25519", "auth": "ecdsa_p256", "chain": "leaf_int"}).json()
    check_provenance(b, False)
    assert 1438 <= b["observed"]["hs_s2c_bytes_median"] <= 1446 and b["observed"]["hs_c2s_bytes_median"] == 274


@pytest.mark.realdata
def test_real_drift(real):
    b = real.get("/api/drift", params={"view": "hs", "workload": "benign_web"}).json()
    check_provenance(b, False)
    assert b["n_rows"] > 0 and all(r["view"] == "hs" for r in b["rows"])


@pytest.mark.realdata
def test_real_detectors(real):
    b = real.get("/api/detectors", params={"detector": "rf", "method": "naive", "profile": "X25519|ecdsa_p256|leaf_int"}).json()
    check_provenance(b, False)
    rec = b["records"][0]
    assert rec["metrics"]["fpr"]["ci_lo"] <= rec["metrics"]["fpr"]["value"] <= rec["metrics"]["fpr"]["ci_hi"]
    rep = real.get("/api/detectors", params={"detector": "ae", "method": "canon_bs_k120_true",
                                             "profile": "mlkem768|mldsa65|leaf_int"}).json()["records"][0]
    assert rep["pcap_level"] is not None and rep["pcap_level"]["n_capture_sets"] == 4


@pytest.mark.realdata
def test_real_pqmix(real):
    b = real.get("/api/pqmix", params={"pi": 0.3, "detector": "rf", "profile": "mlkem768|mldsa65|leaf_int"}).json()
    check_provenance(b, False)
    m = b["methods"]["naive"]
    assert m["fpr_mix"] == pytest.approx(0.3 * m["fpr_profile"] + 0.7 * m["fpr_classical"])


@pytest.mark.realdata
def test_real_stream(real):
    with real.websocket_connect("/api/stream?detector=rf&method=naive&profile=mlkem768|mldsa65|leaf_int&speed=5000&limit=40") as ws:
        msgs = collect(ws)
    assert msgs[0]["replay"] is True and "REPLAY" in msgs[0]["notice"]
    check_provenance(msgs[0], False)
    assert msgs[-1]["type"] == "done" and msgs[-1]["n_flows"] == 40


# ---------------------------------------------------------------------------------------------- sidecar provenance (SYNTHETIC)
def write_meta(csv: Path, commit: str, when: str = "2026-01-02T03:04:05+00:00") -> None:
    import json
    csv.with_suffix(".meta.json").write_text(json.dumps({"code_commit": commit, "generated_at": when, "script": "scripts/x.py"}))


def test_results_commit_unknown_when_no_sidecar_and_served_by_is_head(client):
    p = client.get("/api/detectors", params={"detector": "rf"}).json()["provenance"]
    assert p["results_code_commit"] == "unknown (generated before tracking)"
    assert all(v is None for v in p["results_files"].values())


def test_results_commit_from_sidecars_and_mixed(tmp_path):
    cfg = fx.build(tmp_path)
    write_meta(cfg.results_dir / "detector_baseline.csv", "aaa111-dirty", "2026-01-02T03:04:05+00:00")
    write_meta(cfg.results_dir / "canon_eval.csv", "aaa111-dirty", "2026-01-03T00:00:00+00:00")
    c = TestClient(create_app(cfg))
    p = c.get("/api/pqmix", params={"pi": 0.5, "detector": "rf", "profile": fx.P1}).json()["provenance"]
    assert p["results_code_commit"] == "aaa111-dirty"
    assert p["generated_at"] == "2026-01-03T00:00:00+00:00"                     # newest sidecar time
    assert p["results_files"]["SYNTHETIC_results/detector_baseline.csv"] == {
        "code_commit": "aaa111-dirty", "generated_at": "2026-01-02T03:04:05+00:00", "script": "scripts/x.py"}
    write_meta(cfg.results_dir / "canon_eval.csv", "bbb222")
    p = TestClient(create_app(cfg)).get("/api/pqmix", params={"pi": 0.5, "detector": "rf", "profile": fx.P1}).json()["provenance"]
    assert p["results_code_commit"] == "mixed (see results_files)"
    # one file with a sidecar, one without -> mixed (not silently taken from the one that has it)
    (cfg.results_dir / "canon_eval.meta.json").unlink()
    p = TestClient(create_app(cfg)).get("/api/pqmix", params={"pi": 0.5, "detector": "rf", "profile": fx.P1}).json()["provenance"]
    assert p["results_code_commit"] == "mixed (see results_files)"


def test_malformed_sidecar_is_treated_as_missing(tmp_path):
    cfg = fx.build(tmp_path)
    (cfg.results_dir / "lab_drift.meta.json").write_text("{not json")
    p = TestClient(create_app(cfg)).get("/api/drift").json()["provenance"]
    assert p["results_code_commit"] == "unknown (generated before tracking)"
    (cfg.results_dir / "lab_drift.meta.json").write_text('{"code_commit": "x"}')                  # missing keys
    assert TestClient(create_app(cfg)).get("/api/drift").json()["provenance"]["results_files"]["SYNTHETIC_results/lab_drift.csv"] is None


def test_served_by_commit_is_head_of_the_served_repo(tmp_path):
    cfg = fx.build(tmp_path)
    git = cfg.root / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main")
    (git / "refs" / "heads" / "main").write_text("cafe1234")
    p = TestClient(create_app(cfg)).get("/api/drift").json()["provenance"]
    assert p["served_by_commit"] == "cafe1234" and p["results_code_commit"] == "unknown (generated before tracking)"
