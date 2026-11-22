"""
Unit and integration tests for Component 2:
Collapse-Free JEPA Latent Protocol World Model, Calibrated Surprise Sensor,
and backward-compatible AnomalyDetector integration.
"""

from __future__ import annotations

import json
import math
import random
from typing import List, Tuple

import pytest

from anomaly_detector import AnomalyDetector
import engine.latent_jepa_model as jepa_mod
from engine.latent_jepa_model import (
    ACTION_DIM,
    STATE_DIM,
    LatentProtocolJEPA,
    LatentSurpriseVerdict,
    extract_probe_action_vector,
    extract_response_state_vector,
)


def _make_html_response(
    status_line: bytes = b"HTTP/1.1 200 OK",
    body: bytes = b"<html><body>ok</body></html>",
    *,
    extra_headers: List[bytes] | None = None,
    connection: bytes = b"keep-alive",
    use_chunked: bool = False,
    declared_cl: int | None = None,
) -> bytes:
    headers = [status_line, b"Content-Type: text/html; charset=utf-8", b"Server: nginx/1.25"]
    if connection:
        headers.append(b"Connection: " + connection)
    if use_chunked:
        headers.append(b"Transfer-Encoding: chunked")
    else:
        cl_val = len(body) if declared_cl is None else declared_cl
        headers.append(f"Content-Length: {cl_val}".encode("ascii"))
    if extra_headers:
        headers.extend(extra_headers)
    return b"\r\n".join(headers) + b"\r\n\r\n" + body


def _generate_benign_http_transitions(
    n: int,
    seed: int = 123,
    *,
    fixed_baseline_prev: bool = False,
) -> List[Tuple[List[float], List[float], List[float]]]:
    """
    Generates realistic benign HTTP/1.1 protocol transition tuples across
    multiple normal endpoints with heavy dynamic HTML/JSON body noise.
    """
    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

    def _rand_token(length: int) -> bytes:
        return "".join(rng.choice(alphabet) for _ in range(length)).encode("ascii")

    baseline_prev_resp = _make_html_response(
        b"HTTP/1.1 200 OK",
        b"<html><body>baseline " + (b"x" * 180) + b"</body></html>",
    )
    baseline_prev_state = extract_response_state_vector(baseline_prev_resp, latency_ms=22.0)

    transitions: List[Tuple[List[float], List[float], List[float]]] = []
    for idx in range(n):
        kind = idx % 4
        if kind == 0:
            probe = (
                b"GET /home?ts=" + str(1700000000 + idx).encode("ascii") + b" HTTP/1.1\r\n"
                b"Host: example.local\r\n"
                b"User-Agent: rfchunt-test\r\n\r\n"
            )
            body = (
                b"<html><body><h1>Home</h1><p>nonce="
                + _rand_token(rng.randint(80, 260))
                + b"</p></body></html>"
            )
            next_resp = _make_html_response(b"HTTP/1.1 200 OK", body)
            latency = rng.uniform(15.0, 45.0)
            domain, mutator = "http1_home", "benign_get"
        elif kind == 1:
            payload = b'{"req_id":"' + _rand_token(16) + b'","v":1}'
            probe = (
                b"POST /api/items HTTP/1.1\r\n"
                b"Host: example.local\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
                + payload
            )
            body = (
                b'{"status":"ok","trace":"'
                + _rand_token(rng.randint(90, 240))
                + b'","items":[1,2,3]}'
            )
            next_resp = _make_html_response(
                b"HTTP/1.1 200 OK",
                body,
                extra_headers=[b"X-Request-Id: " + _rand_token(12)],
            )
            latency = rng.uniform(20.0, 55.0)
            domain, mutator = "http1_api", "benign_post"
        elif kind == 2:
            probe = (
                b"GET /old-path HTTP/1.1\r\n"
                b"Host: example.local\r\n\r\n"
            )
            next_resp = _make_html_response(
                b"HTTP/1.1 302 Found",
                b"",
                extra_headers=[b"Location: /new-path"],
            )
            latency = rng.uniform(8.0, 25.0)
            domain, mutator = "http1_redirect", "benign_get"
        else:
            probe = (
                b"GET /missing-" + _rand_token(6) + b" HTTP/1.1\r\n"
                b"Host: example.local\r\n\r\n"
            )
            body = b"<html><body>Not Found: " + _rand_token(rng.randint(80, 180)) + b"</body></html>"
            next_resp = _make_html_response(b"HTTP/1.1 404 Not Found", body)
            latency = rng.uniform(10.0, 30.0)
            domain, mutator = "http1_notfound", "benign_get"

        if fixed_baseline_prev:
            prev_state = list(baseline_prev_state)
        else:
            prev_body = b"<html><body>prev " + _rand_token(rng.randint(90, 220)) + b"</body></html>"
            prev_resp = _make_html_response(b"HTTP/1.1 200 OK", prev_body)
            prev_state = extract_response_state_vector(prev_resp, latency_ms=rng.uniform(15.0, 40.0))

        action = extract_probe_action_vector(
            probe,
            domain=domain,
            mutator_family=mutator,
            pipeline_step=(idx % 3) + 1,
        )
        next_state = extract_response_state_vector(next_resp, latency_ms=latency)
        transitions.append((prev_state, action, next_state))

    return transitions


# ---------------------------------------------------------------------------
# 1. Interface Contract & Feature Extractors
# ---------------------------------------------------------------------------

def test_exports_and_feature_dimensions() -> None:
    assert STATE_DIM == 18
    assert ACTION_DIM == 16

    verdict = LatentSurpriseVerdict(
        surprise_score=0.12,
        threshold=0.50,
        is_anomalous=False,
        calibrated=True,
    )
    assert verdict.stack_profile == "generic"
    assert verdict.backend_label == "latent_jepa_world_model"
    assert verdict.reason == ""

    model = LatentProtocolJEPA()
    assert model.calibrated is False
    assert model.trained_transitions == 0
    assert model.backend_label == "latent_jepa_world_model"
    assert math.isinf(model.threshold)


def test_response_extractor_ignores_dynamic_html_body_noise() -> None:
    resp_a = _make_html_response(
        b"HTTP/1.1 200 OK",
        b"<html><body><h1>Welcome Alice</h1><p>csrf=11111111111111111111111111111111111111111111111111111111111111111111</p></body></html>",
    )
    resp_b = _make_html_response(
        b"HTTP/1.1 200 OK",
        b'{"user":"Bob","timestamp":1999999999,"nonce":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}',
    )

    vec_a = extract_response_state_vector(resp_a, latency_ms=25.0)
    vec_b = extract_response_state_vector(resp_b, latency_ms=25.0)

    assert len(vec_a) == STATE_DIM
    assert len(vec_b) == STATE_DIM
    assert all(math.isfinite(x) for x in vec_a)
    assert vec_a == vec_b


def test_response_extractor_captures_protocol_framing_and_transport_signals() -> None:
    # Dual CL+TE + trailing overflow + Connection: close
    dual_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 5\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
        b"helloEXTRA_SMUGGLED_BYTES"
    )
    vec_dual = extract_response_state_vector(
        dual_resp,
        latency_ms=120.0,
        socket_closed=True,
        trailing_bytes=19,
        canary_matched=True,
        diff_diverged=True,
    )
    assert len(vec_dual) == STATE_DIM
    assert vec_dual[1] == 1.0  # 2xx
    assert vec_dual[5] == 1.0  # CL
    assert vec_dual[6] == 1.0  # TE
    assert vec_dual[7] == 1.0  # dual framing
    assert vec_dual[11] == 1.0  # Connection: close
    assert vec_dual[13] > 0.25  # trailing buffer ratio
    assert vec_dual[15] == 1.0  # socket closed
    assert vec_dual[16] == 1.0  # canary matched
    assert vec_dual[17] == 1.0  # diff diverged

    # Inferred trailing overflow beyond declared CL even when trailing_bytes=0
    overflow_resp = _make_html_response(
        b"HTTP/1.1 200 OK",
        b"12345SMUGGLED_TAIL",
        declared_cl=5,
    )
    vec_overflow = extract_response_state_vector(overflow_resp)
    assert vec_overflow[13] > 0.25

    # HTTP/2 framing
    h2_resp = b"HTTP/2 200\r\n:status: 200\r\ncontent-type: text/plain\r\n\r\nok"
    vec_h2 = extract_response_state_vector(h2_resp)
    assert vec_h2[1] == 1.0
    assert vec_h2[9] == 1.0

    # Empty response (timeout/RST)
    vec_empty = extract_response_state_vector(b"", latency_ms=5500.0)
    assert len(vec_empty) == STATE_DIM
    assert vec_empty[15] == 1.0


def test_probe_action_extractor_captures_mutations_and_is_deterministic() -> None:
    smuggle_probe = (
        b"POST /admin HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"Content-Length: 4\r\n"
        b"Content-Length : 12\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b" folded-header-val\r\n"
        b"Trailer: X-Checksum\r\n\r\n"
        b"4;ext=abc\r\n"
        b"test\r\n"
        b"0\r\n"
        b"X-Checksum: \xff\r\n\r\n"
    )
    v1 = extract_probe_action_vector(
        smuggle_probe,
        domain="desync",
        mutator_family="cl_te_obsfold",
        pipeline_step=2,
    )
    v2 = extract_probe_action_vector(
        smuggle_probe,
        domain="desync",
        mutator_family="cl_te_obsfold",
        pipeline_step=2,
    )
    assert len(v1) == ACTION_DIM
    assert v1 == v2
    assert v1[1] == 1.0  # POST -> body write method
    assert v1[4] == 1.0  # duplicate CL
    assert v1[5] == 1.0  # TE
    assert v1[6] == 1.0  # obs-fold / ws-before-colon
    assert v1[7] == 1.0  # chunk extension
    assert v1[8] == 1.0  # trailers
    assert v1[10] == 1.0  # non-ASCII byte 0xff
    assert v1[12] != 0.0 or v1[13] != 0.0  # hashed domain
    assert v1[14] != 0.0  # hashed mutator

    h2_probe = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n:method: GET\r\n:path: /\r\n"
    vh2 = extract_probe_action_vector(h2_probe, domain="h2", mutator_family="preface")
    assert vh2[2] == 1.0  # PRI tunnel/h2 method
    assert vh2[9] == 1.0  # H2 flag


# ---------------------------------------------------------------------------
# 2. Cold-Start Safety Gate (< 200 transitions)
# ---------------------------------------------------------------------------

def test_cold_start_gate_blocks_calibration_below_min_transitions() -> None:
    model = LatentProtocolJEPA(min_benign_transitions=200, seed=42)
    transitions = _generate_benign_http_transitions(199, seed=10)

    report = model.fit_and_calibrate(transitions, epochs=10)
    assert report == {
        "calibrated": False,
        "reason": "insufficient_real_transitions",
        "count": 199,
        "required": 200,
    }
    assert model.calibrated is False
    assert model.trained_transitions == 0
    assert model.predict_anomaly_score(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n") is None

    s0, a0, s1 = transitions[0]
    verdict = model.score_transition(s0, a0, s1)
    assert verdict.calibrated is False
    assert verdict.is_anomalous is False
    assert verdict.reason == "model_uncalibrated_cold_start"


# ---------------------------------------------------------------------------
# 3. Analytical Gradient Verification (Central Finite Differences)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("use_numpy", [True, False])
def test_analytical_gradients_match_finite_differences(
    monkeypatch: pytest.MonkeyPatch,
    use_numpy: bool,
) -> None:
    if use_numpy and not jepa_mod._HAS_NUMPY:
        pytest.skip("NumPy not available in environment")
    if not use_numpy:
        monkeypatch.setattr(jepa_mod, "_HAS_NUMPY", False)

    model = LatentProtocolJEPA(state_dim=6, action_dim=4, latent_dim=4, hidden_dim=6, seed=11)
    rng = random.Random(99)
    B = 5
    x_prev = [[rng.gauss(0.0, 1.0) for _ in range(6)] for _ in range(B)]
    act = [[rng.gauss(0.0, 1.0) for _ in range(4)] for _ in range(B)]
    x_next = [[rng.gauss(0.0, 1.0) for _ in range(6)] for _ in range(B)]

    def _compute_loss_and_grads() -> Tuple[float, dict, dict]:
        if use_numpy:
            xp = jepa_mod.np.asarray(x_prev, dtype=jepa_mod.np.float64)
            aa = jepa_mod.np.asarray(act, dtype=jepa_mod.np.float64)
            xn = jepa_mod.np.asarray(x_next, dtype=jepa_mod.np.float64)
            zp, cp = jepa_mod._np_encoder_forward(xp, model._online_params)
            zno, cn = jepa_mod._np_encoder_forward(xn, model._online_params)
            znt, _ = jepa_mod._np_encoder_forward(xn, model._target_params)
            zh, cpred = jepa_mod._np_predictor_forward(zp, aa, model._pred_params)
            diff = zh - znt
            pred_loss = float(jepa_mod.np.mean(jepa_mod.np.sum(diff * diff, axis=1)))
            dzh = (2.0 / float(B)) * diff
            z_pooled = jepa_mod.np.concatenate([zp, zno], axis=0)
            vic_loss, gvic = jepa_mod._np_vicreg_loss_and_grad(z_pooled, jepa_mod._LAMBDA_VAR, jepa_mod._LAMBDA_COV)
            dzp, pgrads = jepa_mod._np_predictor_backward(dzh, model._pred_params, cpred)
            egp = jepa_mod._np_encoder_backward(dzp + gvic[:B], model._online_params, cp)
            egn = jepa_mod._np_encoder_backward(gvic[B:], model._online_params, cn)
            egrads = {k: egp[k] + egn[k] for k in model._online_params}
            return pred_loss + vic_loss, egrads, pgrads
        else:
            zp, cp = jepa_mod._py_encoder_forward(x_prev, model._online_params)
            zno, cn = jepa_mod._py_encoder_forward(x_next, model._online_params)
            znt, _ = jepa_mod._py_encoder_forward(x_next, model._target_params)
            zh, cpred = jepa_mod._py_predictor_forward(zp, act, model._pred_params)
            inv = 1.0 / float(B)
            pred_loss = sum((zh[i][j] - znt[i][j]) ** 2 for i in range(B) for j in range(4)) * inv
            dzh = [[2.0 * inv * (zh[i][j] - znt[i][j]) for j in range(4)] for i in range(B)]
            vic_loss, gvic = jepa_mod._py_vicreg_loss_and_grad(zp + zno, jepa_mod._LAMBDA_VAR, jepa_mod._LAMBDA_COV)
            dzp, pgrads = jepa_mod._py_predictor_backward(dzh, model._pred_params, cpred)
            dzp_tot = [[dzp[i][j] + gvic[i][j] for j in range(4)] for i in range(B)]
            egp = jepa_mod._py_encoder_backward(dzp_tot, model._online_params, cp)
            egn = jepa_mod._py_encoder_backward(gvic[B:], model._online_params, cn)
            egrads = {}
            for k in model._online_params:
                if isinstance(egp[k][0], list):
                    egrads[k] = [
                        [egp[k][r][c] + egn[k][r][c] for c in range(len(egp[k][0]))]
                        for r in range(len(egp[k]))
                    ]
                else:
                    egrads[k] = [egp[k][c] + egn[k][c] for c in range(len(egp[k]))]
            return pred_loss + vic_loss, egrads, pgrads

    _, enc_grads, pred_grads = _compute_loss_and_grads()
    eps = 1e-6

    checks = [
        (model._online_params, enc_grads, "W1", (1, 2)),
        (model._online_params, enc_grads, "b1", (3,)),
        (model._online_params, enc_grads, "ln_g", (2,)),
        (model._online_params, enc_grads, "ln_b", (4,)),
        (model._online_params, enc_grads, "W2", (2, 1)),
        (model._online_params, enc_grads, "b2", (0,)),
        (model._online_params, enc_grads, "W_skip", (2, 1)),
        (model._pred_params, pred_grads, "Wp1", (3, 1)),
        (model._pred_params, pred_grads, "bp1", (2,)),
        (model._pred_params, pred_grads, "Wp2", (1, 3)),
        (model._pred_params, pred_grads, "bp2", (2,)),
    ]

    for pdict, gdict, key, coord in checks:
        if len(coord) == 2:
            r, c = coord
            orig = float(pdict[key][r][c])
            pdict[key][r][c] = orig + eps
            loss_plus, _, _ = _compute_loss_and_grads()
            pdict[key][r][c] = orig - eps
            loss_minus, _, _ = _compute_loss_and_grads()
            pdict[key][r][c] = orig
            analytic = float(gdict[key][r][c])
        else:
            c = coord[0]
            orig = float(pdict[key][c])
            pdict[key][c] = orig + eps
            loss_plus, _, _ = _compute_loss_and_grads()
            pdict[key][c] = orig - eps
            loss_minus, _, _ = _compute_loss_and_grads()
            pdict[key][c] = orig
            analytic = float(gdict[key][c])

        numeric = (loss_plus - loss_minus) / (2.0 * eps)
        assert abs(analytic - numeric) < 1e-5, f"{key}{coord}: analytic={analytic} vs numeric={numeric}"


# ---------------------------------------------------------------------------
# 4. EMA Non-Collapse, Calibrated p99 Surprise, Subtle Divergence vs Body Noise
# ---------------------------------------------------------------------------

def test_ema_non_collapse_and_calibrated_surprise_detection() -> None:
    train_data = _generate_benign_http_transitions(260, seed=42)
    model = LatentProtocolJEPA(
        ema_decay=0.99,
        min_benign_transitions=200,
        quantile=0.99,
        stack_profile="nginx_http1",
        seed=42,
    )

    init_target_w1 = model.to_dict()["target_encoder"]["W1"]
    report = model.fit_and_calibrate(train_data, epochs=25, lr=0.01, val_ratio=0.25)

    assert report["calibrated"] is True
    assert model.calibrated is True
    assert model.trained_transitions == 260
    assert math.isfinite(model.threshold) and model.threshold > 0.0

    # Verify EMA target encoder updated smoothly and stayed distinct from online encoder
    after_dict = model.to_dict()
    assert after_dict["target_encoder"]["W1"] != init_target_w1
    assert after_dict["target_encoder"]["W1"] != after_dict["online_encoder"]["W1"]

    # Verify collapse-free embeddings (positive variance across ALL latent dimensions)
    states = [t[2] for t in train_data]
    online_stats = model.embedding_statistics(states, use_target_encoder=False)
    target_stats = model.embedding_statistics(states, use_target_encoder=True)
    assert online_stats["min_std"] > 0.05
    assert target_stats["min_std"] > 0.05
    assert online_stats["mean_std"] > 0.25
    assert target_stats["mean_std"] > 0.25
    assert report["embedding_min_std"] > 0.05

    # Unseen benign transitions with wildly different dynamic HTML/JSON bodies must NOT trigger
    unseen_benign = _generate_benign_http_transitions(40, seed=9999)
    benign_flags = [model.score_transition(p, a, n).is_anomalous for p, a, n in unseen_benign]
    false_positive_rate = sum(1 for f in benign_flags if f) / float(len(benign_flags))
    assert false_positive_rate <= 0.10

    # Specific dynamic HTML noise invariance check on normal GET /home
    prev_state = extract_response_state_vector(
        _make_html_response(b"HTTP/1.1 200 OK", b"<html><body>prev " + b"a" * 150 + b"</body></html>"),
        latency_ms=25.0,
    )
    benign_probe = b"GET /home?ts=9999999 HTTP/1.1\r\nHost: example.local\r\nUser-Agent: rfchunt-test\r\n\r\n"
    benign_action = extract_probe_action_vector(
        benign_probe,
        domain="http1_home",
        mutator_family="benign_get",
        pipeline_step=1,
    )
    noisy_html_resp = _make_html_response(
        b"HTTP/1.1 200 OK",
        b"<html><body><div id='r'>COMPLETELY_NEW_HTML_NONCE_9876543210_ABCDEF_" + (b"Z" * 170) + b"</div></body></html>",
    )
    noisy_html_verdict = model.score_transition(
        prev_state,
        benign_action,
        extract_response_state_vector(noisy_html_resp, latency_ms=28.0),
    )
    assert noisy_html_verdict.calibrated is True
    assert noisy_html_verdict.is_anomalous is False
    assert noisy_html_verdict.stack_profile == "nginx_http1"
    assert noisy_html_verdict.backend_label == "latent_jepa_world_model"

    # Subtle protocol divergences (none trigger regex double-HTML / binary-blend checks!)
    divergences = [
        (
            "te_and_conn_close",
            extract_response_state_vector(
                _make_html_response(
                    b"HTTP/1.1 200 OK",
                    b"<html><body>ok " + b"x" * 140 + b"</body></html>",
                    connection=b"close",
                    use_chunked=True,
                ),
                latency_ms=30.0,
            ),
        ),
        (
            "trailing_smuggled_bytes",
            extract_response_state_vector(
                _make_html_response(
                    b"HTTP/1.1 200 OK",
                    b"<html><body>ok " + b"x" * 140 + b"</body></html>SMUGGLED_QUEUE_POISON",
                    declared_cl=170,
                ),
                latency_ms=30.0,
                trailing_bytes=22,
            ),
        ),
        (
            "dual_cl_te_framing",
            extract_response_state_vector(
                _make_html_response(
                    b"HTTP/1.1 200 OK",
                    b"<html><body>ok " + b"x" * 140 + b"</body></html>",
                    extra_headers=[b"Transfer-Encoding: chunked"],
                ),
                latency_ms=30.0,
            ),
        ),
        (
            "unexpected_500_and_rst",
            extract_response_state_vector(
                _make_html_response(b"HTTP/1.1 500 Internal Server Error", b"err", connection=b"close"),
                latency_ms=40.0,
                socket_closed=True,
            ),
        ),
        (
            "differential_divergence",
            extract_response_state_vector(
                _make_html_response(b"HTTP/1.1 200 OK", b"<html><body>ok " + b"x" * 140 + b"</body></html>"),
                latency_ms=30.0,
                diff_diverged=True,
            ),
        ),
    ]

    for label, div_state in divergences:
        v = model.score_transition(prev_state, benign_action, div_state)
        assert v.calibrated is True, label
        assert v.is_anomalous is True, f"Expected anomaly for {label}: score={v.surprise_score}, thresh={v.threshold}"
        assert v.surprise_score > v.threshold, label

    # Pre-execution probe anomaly scoring (ProtocolWorldModel integration)
    baseline_bytes = _make_html_response(b"HTTP/1.1 200 OK", b"<html><body>" + b"x" * 150 + b"</body></html>")
    benign_pred = model.predict_anomaly_score(
        benign_probe,
        baseline_response=baseline_bytes,
        domain="http1_home",
        mutator_family="benign_get",
    )
    smuggle_pred = model.predict_anomaly_score(
        (
            b"POST /home HTTP/1.1\r\n"
            b"Host: example.local\r\n"
            b"Content-Length: 4\r\n"
            b"Content-Length : 9\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b" obs-fold\r\n"
            b"Trailer: X-Evil\r\n\r\n"
            b"4;ext=1\r\n\xffabc\r\n0\r\nX-Evil: 1\r\n\r\n"
        ),
        baseline_response=baseline_bytes,
        domain="desync_attack",
        mutator_family="cl_te_smuggle",
    )
    assert benign_pred is not None and smuggle_pred is not None
    assert 0.0 <= benign_pred <= 1.0
    assert 0.0 <= smuggle_pred <= 1.0
    assert smuggle_pred > benign_pred


def test_fixed_baseline_prev_state_still_avoids_collapse() -> None:
    transitions = _generate_benign_http_transitions(220, seed=77, fixed_baseline_prev=True)
    model = LatentProtocolJEPA(min_benign_transitions=200, seed=77)
    report = model.fit_and_calibrate(transitions, epochs=20, lr=0.01)
    assert report["calibrated"] is True
    assert report["embedding_min_std"] > 0.05


# ---------------------------------------------------------------------------
# 5. NumPy vs Pure-Python Exact Numerical Parity
# ---------------------------------------------------------------------------

def test_numpy_and_pure_python_fallback_produce_identical_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not jepa_mod._HAS_NUMPY:
        pytest.skip("NumPy not installed; pure-Python path already tested directly")

    transitions = _generate_benign_http_transitions(210, seed=314)

    model_np = LatentProtocolJEPA(min_benign_transitions=200, seed=55)
    assert model_np._use_numpy is True
    rep_np = model_np.fit_and_calibrate(transitions, epochs=12, lr=0.01)

    monkeypatch.setattr(jepa_mod, "_HAS_NUMPY", False)
    model_py = LatentProtocolJEPA(min_benign_transitions=200, seed=55)
    assert model_py._use_numpy is False
    rep_py = model_py.fit_and_calibrate(transitions, epochs=12, lr=0.01)

    assert rep_np["math_backend"] == "numpy"
    assert rep_py["math_backend"] == "python"
    assert abs(model_np.threshold - model_py.threshold) < 1e-8
    assert abs(rep_np["final_loss"] - rep_py["final_loss"]) < 1e-8

    p, a, n = transitions[0]
    v_np = model_np.score_transition(p, a, n)
    v_py = model_py.score_transition(p, a, n)
    assert abs(v_np.surprise_score - v_py.surprise_score) < 1e-8
    assert v_np.is_anomalous == v_py.is_anomalous

    probe = b"GET /home HTTP/1.1\r\nHost: example.local\r\n\r\n"
    s_np = model_np.predict_anomaly_score(probe, domain="http1_home")
    s_py = model_py.predict_anomaly_score(probe, domain="http1_home")
    assert s_np is not None and s_py is not None
    assert abs(s_np - s_py) < 1e-8


# ---------------------------------------------------------------------------
# 6. JSON Roundtrip Serialization
# ---------------------------------------------------------------------------

def test_json_roundtrip_serialization_preserves_exact_scoring() -> None:
    transitions = _generate_benign_http_transitions(220, seed=2026)
    model = LatentProtocolJEPA(
        min_benign_transitions=200,
        stack_profile="envoy_h2",
        seed=2026,
    )
    model.fit_and_calibrate(transitions, epochs=15, lr=0.01)

    raw_json = json.dumps(model.to_dict())
    loaded_dict = json.loads(raw_json)
    restored = LatentProtocolJEPA.from_dict(loaded_dict)

    assert restored.calibrated is True
    assert restored.trained_transitions == 220
    assert restored.stack_profile == "envoy_h2"
    assert restored.backend_label == "latent_jepa_world_model"
    assert abs(restored.threshold - model.threshold) < 1e-12

    p, a, n = transitions[5]
    v_orig = model.score_transition(p, a, n)
    v_rest = restored.score_transition(p, a, n)
    assert abs(v_orig.surprise_score - v_rest.surprise_score) < 1e-12
    assert v_orig.is_anomalous == v_rest.is_anomalous

    # Uncalibrated model roundtrip
    cold = LatentProtocolJEPA(stack_profile="cold_stack")
    cold_restored = LatentProtocolJEPA.from_dict(json.loads(json.dumps(cold.to_dict())))
    assert cold_restored.calibrated is False
    assert math.isinf(cold_restored.threshold)
    assert cold_restored.predict_anomaly_score(b"GET / HTTP/1.1\r\n\r\n") is None


# ---------------------------------------------------------------------------
# 7. AnomalyDetector Integration & Backward Compatibility
# ---------------------------------------------------------------------------

def test_anomaly_detector_backward_compatibility_and_jepa_verdict() -> None:
    baseline = _make_html_response(b"HTTP/1.1 200 OK", b"<html><body>baseline</body></html>")
    clean_other = _make_html_response(
        b"HTTP/1.1 200 OK",
        b"<html><body>subtle framing shift</body></html>",
        connection=b"close",
        use_chunked=True,
    )

    # Legacy calls without jepa_verdict keep exact existing behavior
    assert AnomalyDetector.analyze_response(baseline) == []
    assert AnomalyDetector.analyze_response(baseline, baseline_response=baseline) == []
    assert AnomalyDetector.analyze_response(b"") == []
    assert AnomalyDetector.analyze_response(clean_other, baseline_response=baseline) == []

    double_html = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n<html>1</html><html>2</html>"
    anoms_legacy = AnomalyDetector.analyze_response(double_html)
    assert any(a["type"] == "double_html" for a in anoms_legacy)

    # Uncalibrated verdict MUST NEVER fire (even if is_anomalous=True were forced)
    uncal = LatentSurpriseVerdict(
        surprise_score=9.9,
        threshold=0.5,
        is_anomalous=True,
        calibrated=False,
        stack_profile="nginx",
    )
    assert AnomalyDetector.analyze_response(clean_other, baseline_response=baseline, jepa_verdict=uncal) == []

    # Calibrated non-anomalous verdict MUST NOT fire
    cal_ok = LatentSurpriseVerdict(
        surprise_score=0.05,
        threshold=0.5,
        is_anomalous=False,
        calibrated=True,
        stack_profile="nginx",
    )
    assert AnomalyDetector.analyze_response(clean_other, baseline_response=baseline, jepa_verdict=cal_ok) == []

    # Calibrated anomalous verdict MUST be suppressed when raw_response == baseline_response
    cal_anom = LatentSurpriseVerdict(
        surprise_score=1.85,
        threshold=0.42,
        is_anomalous=True,
        calibrated=True,
        stack_profile="nginx",
        reason="latent_surprise_exceeded_p99",
    )
    assert AnomalyDetector.analyze_response(baseline, baseline_response=baseline, jepa_verdict=cal_anom) == []

    # Calibrated anomalous verdict appends latent_transition_surprise when response != baseline
    anoms = AnomalyDetector.analyze_response(clean_other, baseline_response=baseline, jepa_verdict=cal_anom)
    jepa_anoms = [a for a in anoms if a["type"] == "latent_transition_surprise"]
    assert len(jepa_anoms) == 1
    assert "1.850000" in jepa_anoms[0]["description"]
    assert "0.420000" in jepa_anoms[0]["description"]
    assert "nginx" in jepa_anoms[0]["description"]

    # Also supports dict verdicts and unexpected empty/RST responses vs non-empty baseline
    anoms_rst = AnomalyDetector.analyze_response(b"", baseline_response=baseline, jepa_verdict=cal_anom.to_dict())
    assert len(anoms_rst) == 1
    assert anoms_rst[0]["type"] == "latent_transition_surprise"


def test_end_to_end_jepa_to_anomaly_detector_pipeline() -> None:
    transitions = _generate_benign_http_transitions(240, seed=505)
    model = LatentProtocolJEPA(min_benign_transitions=200, stack_profile="test_proxy", seed=505)
    model.fit_and_calibrate(transitions, epochs=25, lr=0.01)

    baseline = _make_html_response(b"HTTP/1.1 200 OK", b"<html><body>base " + b"x" * 160 + b"</body></html>")
    prev_state = extract_response_state_vector(baseline, latency_ms=25.0)
    probe = b"GET /home?ts=42 HTTP/1.1\r\nHost: example.local\r\nUser-Agent: rfchunt-test\r\n\r\n"
    action = extract_probe_action_vector(probe, domain="http1_home", mutator_family="benign_get")

    # Benign response with completely new HTML body -> 0 anomalies
    benign_resp = _make_html_response(
        b"HTTP/1.1 200 OK",
        b"<html><body>dynamic_body_xyz_" + b"Q" * 175 + b"</body></html>",
    )
    benign_verdict = model.score_transition(
        prev_state,
        action,
        extract_response_state_vector(benign_resp, latency_ms=26.0),
    )
    assert AnomalyDetector.analyze_response(benign_resp, baseline_response=baseline, jepa_verdict=benign_verdict) == []

    # Subtle framing divergence (still 200 OK, clean HTML, but switched to chunked + Connection: close)
    subtle_desync = _make_html_response(
        b"HTTP/1.1 200 OK",
        b"<html><body>dynamic_body_xyz_" + b"Q" * 175 + b"</body></html>",
        connection=b"close",
        use_chunked=True,
    )
    div_verdict = model.score_transition(
        prev_state,
        action,
        extract_response_state_vector(subtle_desync, latency_ms=28.0),
    )
    anoms = AnomalyDetector.analyze_response(subtle_desync, baseline_response=baseline, jepa_verdict=div_verdict)
    assert any(a["type"] == "latent_transition_surprise" for a in anoms)


def test_homogeneous_single_endpoint_server_catches_subtle_divergence() -> None:
    rng = random.Random(17)
    base_probe = b"GET /index.html HTTP/1.1\r\nHost: single.local\r\n\r\n"
    action = extract_probe_action_vector(base_probe, domain="single", mutator_family="benign")
    transitions = []
    for _ in range(220):
        s_prev = extract_response_state_vector(
            _make_html_response(body=b"<html>" + b"a" * rng.randint(120, 400) + b"</html>"),
            latency_ms=rng.uniform(10.0, 60.0),
        )
        s_next = extract_response_state_vector(
            _make_html_response(body=b"<html>" + b"b" * rng.randint(120, 400) + b"</html>"),
            latency_ms=rng.uniform(10.0, 60.0),
        )
        transitions.append((s_prev, action, s_next))

    model = LatentProtocolJEPA(min_benign_transitions=200, stack_profile="single_endpoint", seed=17)
    report = model.fit_and_calibrate(transitions, epochs=25, lr=0.01)
    assert report["calibrated"] is True
    assert report["embedding_min_std"] > 0.05

    benign_next = extract_response_state_vector(
        _make_html_response(body=b"<html>NEW_NONCE_BODY_" + b"Q" * 240 + b"</html>"),
        latency_ms=35.0,
    )
    divergent_next = extract_response_state_vector(
        _make_html_response(
            body=b"<html>NEW_NONCE_BODY_" + b"Q" * 240 + b"</html>",
            connection=b"close",
            use_chunked=True,
        ),
        latency_ms=35.0,
    )
    v_ok = model.score_transition(transitions[0][0], action, benign_next)
    v_bad = model.score_transition(transitions[0][0], action, divergent_next)
    assert v_ok.is_anomalous is False
    assert v_bad.is_anomalous is True
    assert v_bad.surprise_score > v_bad.threshold


@pytest.mark.parametrize("seed", [7, 42, 101])
def test_multi_seed_stability_and_non_collapse(seed: int) -> None:
    transitions = _generate_benign_http_transitions(230, seed=seed)
    model = LatentProtocolJEPA(min_benign_transitions=200, seed=seed)
    report = model.fit_and_calibrate(transitions, epochs=25, lr=0.01)
    assert report["calibrated"] is True
    assert report["embedding_min_std"] > 0.05

    prev_s, act, _ = transitions[0]
    desync_s = extract_response_state_vector(
        _make_html_response(
            b"HTTP/1.1 200 OK",
            b"<html><body>ok " + b"x" * 140 + b"</body></html>",
            connection=b"close",
            use_chunked=True,
        ),
        latency_ms=30.0,
    )
    v_desync = model.score_transition(prev_s, act, desync_s)
    assert v_desync.is_anomalous is True


def test_edge_cases_and_input_validation() -> None:
    # Arbitrary binary garbage, LF-only headers, malformed CL, 100 Continue, HTTP/3, conflicting Connection
    samples = [
        bytes(range(256)),
        b"HTTP/1.1 100 Continue\nContent-Length: notanint\nConnection: close, keep-alive\n\nbody",
        b"HTTP/3 200 OK\r\ncontent-length: 2\r\n\r\nok",
        b"RAW_NON_HTTP_BANNER",
        b"",
    ]
    for raw in samples:
        sv = extract_response_state_vector(raw, latency_ms=-5.0, trailing_bytes=-1)
        av = extract_probe_action_vector(raw, pipeline_step=-2)
        assert len(sv) == STATE_DIM and all(math.isfinite(x) for x in sv)
        assert len(av) == ACTION_DIM and all(math.isfinite(x) for x in av)

    model = LatentProtocolJEPA()
    with pytest.raises(ValueError):
        model.score_transition([0.0] * (STATE_DIM - 1), [0.0] * ACTION_DIM, [0.0] * STATE_DIM)
    with pytest.raises(ValueError):
        model.score_transition([float("nan")] * STATE_DIM, [0.0] * ACTION_DIM, [0.0] * STATE_DIM)
    with pytest.raises(ValueError):
        LatentProtocolJEPA.from_dict({"online_encoder": {"W1": [[1.0]]}})

