"""
Collapse-Free JEPA Latent Protocol World Model & Calibrated Surprise Sensor.

Implements a clean-room Joint Embedding Predictive Architecture (JEPA) over
structured HTTP/TLS wire transitions without reconstructing raw HTML/JSON body
pixels and without requiring PyTorch:

- Protocol state/action feature extractors (`STATE_DIM = 18`, `ACTION_DIM = 16`)
  capturing status class, framing semantics, connection lifecycle, residual
  buffer ratios, timing, and probe structural mutations while ignoring dynamic
  body noise.
- Online Encoder E_theta (Linear -> LayerNorm -> SiLU -> Linear) paired with a
  stop-gradient Exponential Moving Average (EMA) Target Encoder E_bar_theta and
  a residual Forward Dynamics Predictor P_phi(z_t, a_t) -> z_hat_{t+1}.
- VICReg-style variance and off-diagonal covariance regularization to prevent
  representation collapse.
- Strict real-data cold-start gate (`min_benign_transitions`, default 200) and
  split-conformal empirical quantile threshold calibration.
- Optional NumPy float64 acceleration with an identical pure-Python stdlib
  fallback.
"""

from __future__ import annotations

import hashlib
import math
import random
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import numpy as np  # type: ignore[import-not-found]

    _HAS_NUMPY = True
except ImportError:  # pragma: no cover
    np = None  # type: ignore[assignment]
    _HAS_NUMPY = False

__all__ = [
    "STATE_DIM",
    "ACTION_DIM",
    "LatentSurpriseVerdict",
    "extract_response_state_vector",
    "extract_probe_action_vector",
    "LatentProtocolJEPA",
]

STATE_DIM: int = 18
ACTION_DIM: int = 16

_STATUS_LINE_RE = re.compile(rb"^HTTP/(\d)(?:\.(\d))?\s+(\d{3})\b", re.IGNORECASE)
_EMBEDDED_STATUS_RE = re.compile(rb"(?:^|\r\n|\n)HTTP/\d(?:\.\d)?\s+\d{3}\b", re.IGNORECASE)
_H2_STATUS_PSEUDO_RE = re.compile(rb"(?:^|\r\n|\n):status\s*:\s*(\d{3})\b", re.IGNORECASE)
_WS_BEFORE_COLON_RE = re.compile(rb"^[^\r\n:]+[ \t]+:")
_CHUNK_EXT_RE = re.compile(rb"(?:^|\r\n|\n)[0-9a-fA-F]+[ \t]*;[^\r\n]*(?:\r\n|\n)")
_CHUNK_TRAILER_RE = re.compile(rb"(?:^|\r\n|\n)0(?:;[^\r\n]*)?\r?\n[A-Za-z0-9\-]+:")

_SAFE_READ_METHODS = frozenset({b"GET", b"HEAD", b"OPTIONS", b"TRACE"})
_BODY_WRITE_METHODS = frozenset({b"POST", b"PUT", b"PATCH", b"DELETE"})
_TUNNEL_METHODS = frozenset({b"CONNECT", b"PRI"})

_LAYER_NORM_EPS = 1e-5
_VICREG_VAR_EPS = 1e-4
_VICREG_GAMMA = 0.5
_LAMBDA_VAR = 0.25
_LAMBDA_COV = 0.02
_WEIGHT_DECAY = 2e-2
_MAX_GRAD_NORM = 5.0
_MIN_STATE_SCALE = 0.25
_MIN_ACTION_SCALE = 1.0


@dataclass
class LatentSurpriseVerdict:
    """Calibrated latent forward-dynamics surprise verdict for a protocol transition."""

    surprise_score: float
    threshold: float
    is_anomalous: bool
    calibrated: bool
    stack_profile: str = "generic"
    backend_label: str = "latent_jepa_world_model"
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "surprise_score": float(self.surprise_score),
            "threshold": float(self.threshold),
            "is_anomalous": bool(self.is_anomalous),
            "calibrated": bool(self.calibrated),
            "stack_profile": str(self.stack_profile),
            "backend_label": str(self.backend_label),
            "reason": str(self.reason),
        }


def _split_headers_and_body(raw_message: bytes) -> Tuple[bytes, bytes, bool]:
    """Splits raw HTTP bytes into header block and body without decoding body text."""
    idx = raw_message.find(b"\r\n\r\n")
    if idx != -1:
        return raw_message[:idx], raw_message[idx + 4 :], True
    idx_lf = raw_message.find(b"\n\n")
    if idx_lf != -1:
        return raw_message[:idx_lf], raw_message[idx_lf + 2 :], True
    return raw_message, b"", False


def _stable_hash_features(text: str, count: int) -> List[float]:
    """Deterministic SHA-256 projection of categorical labels into [-1.0, 1.0]."""
    norm = (text or "").strip().lower()
    if not norm:
        return [0.0] * count
    digest = hashlib.sha256(norm.encode("utf-8")).digest()
    out: List[float] = []
    denom = float((1 << 32) - 1)
    for i in range(count):
        offset = (i * 4) % (len(digest) - 3)
        val = int.from_bytes(digest[offset : offset + 4], "big")
        out.append((val / denom) * 2.0 - 1.0)
    return out


def _log_bucket_body_size(body_len: int) -> float:
    """
    Coarse order-of-magnitude log-bucketed body size in [0.0, 1.0].
    Insensitive to small dynamic HTML/JSON jitter (timestamps, nonces, tokens)
    while distinguishing empty bodies from non-empty leaks and major size shifts.
    """
    if body_len <= 0:
        return 0.0
    bucket = 1.0 + math.floor(math.log10(float(body_len)))
    return min(1.0, bucket / 7.0)


def extract_response_state_vector(
    raw_response: bytes,
    *,
    latency_ms: float = 0.0,
    socket_closed: bool = False,
    trailing_bytes: int = 0,
    canary_matched: bool = False,
    diff_diverged: bool = False,
) -> List[float]:
    """
    Extracts a fixed-length (`STATE_DIM = 18`) structural protocol state vector
    from raw wire response bytes and transport observations.

    Raw HTML/JSON body pixels are stripped: only framing semantics, status class,
    header metadata, connection lifecycle, coarse log-bucketed body size,
    trailing buffer overflow ratio, timing, transport termination, canary status,
    and differential divergence are retained.
    """
    data = bytes(raw_response) if raw_response else b""

    status_1xx_malformed = 0.0
    status_2xx = 0.0
    status_3xx = 0.0
    status_4xx = 0.0
    status_5xx = 0.0

    framing_cl = 0.0
    framing_te = 0.0
    framing_dual = 0.0
    framing_eof = 0.0
    framing_h2 = 0.0

    header_count_norm = 0.0
    connection_mode = 0.0
    log_body_size = 0.0
    inferred_trailing = 0

    if data:
        header_block, body_bytes, has_sep = _split_headers_and_body(data)
        lines = header_block.splitlines()
        first_line = lines[0].strip() if lines else b""

        status_code: Optional[int] = None
        is_h2 = False

        m_status = _STATUS_LINE_RE.match(first_line)
        if m_status:
            major = int(m_status.group(1))
            status_code = int(m_status.group(3))
            if major >= 2:
                is_h2 = True
        else:
            m_h2 = _H2_STATUS_PSEUDO_RE.search(header_block)
            if m_h2:
                status_code = int(m_h2.group(1))
                is_h2 = True
            elif b"PRI * HTTP/2.0" in data[:64]:
                is_h2 = True

        if status_code is not None:
            if 200 <= status_code < 300:
                status_2xx = 1.0
            elif 300 <= status_code < 400:
                status_3xx = 1.0
            elif 400 <= status_code < 500:
                status_4xx = 1.0
            elif 500 <= status_code < 600:
                status_5xx = 1.0
            else:
                status_1xx_malformed = 1.0
        else:
            status_1xx_malformed = 1.0

        header_count = 0
        cl_values: List[Optional[int]] = []
        te_count = 0
        has_conn_close = False
        has_conn_keep_alive = False

        start_idx = 1 if m_status else 0
        for line in lines[start_idx:]:
            if not line or b":" not in line:
                continue
            raw_name, raw_val = line.split(b":", 1)
            name = raw_name.strip().lower()
            if not name:
                continue
            header_count += 1
            val_lower = raw_val.strip().lower()

            if raw_name.startswith(b":"):
                is_h2 = True
            if name == b"content-length":
                try:
                    cl_values.append(int(val_lower.split(b",", 1)[0].strip()))
                except ValueError:
                    cl_values.append(None)
            elif name == b"transfer-encoding":
                te_count += 1
            elif name == b"connection":
                tokens = {tok.strip() for tok in val_lower.split(b",")}
                if b"close" in tokens or b"close" in val_lower:
                    has_conn_close = True
                if b"keep-alive" in tokens or b"keep-alive" in val_lower:
                    has_conn_keep_alive = True

        status_line_count = len(_EMBEDDED_STATUS_RE.findall(data))
        has_cl = len(cl_values) > 0
        has_te = te_count > 0

        framing_cl = 1.0 if has_cl else 0.0
        framing_te = 1.0 if has_te else 0.0
        if (has_cl and has_te) or len(cl_values) >= 2 or status_line_count >= 2:
            framing_dual = 1.0
        framing_h2 = 1.0 if is_h2 else 0.0
        if not has_cl and not has_te and not is_h2:
            framing_eof = 1.0

        header_count_norm = min(1.0, math.log1p(float(header_count)) / math.log1p(40.0))

        if has_conn_close and has_conn_keep_alive:
            connection_mode = 0.5
        elif has_conn_close:
            connection_mode = 1.0
        elif has_conn_keep_alive:
            connection_mode = -1.0
        else:
            connection_mode = 0.0

        body_len = len(body_bytes) if has_sep else 0
        log_body_size = _log_bucket_body_size(body_len)

        if has_sep and len(cl_values) == 1 and not has_te:
            declared_cl = cl_values[0]
            if declared_cl is not None and declared_cl >= 0 and body_len > declared_cl:
                inferred_trailing = body_len - declared_cl

    eff_trailing = max(max(0, int(trailing_bytes)), inferred_trailing)
    if eff_trailing > 0:
        denom = max(1.0, float(len(data) + max(0, int(trailing_bytes))))
        trailing_ratio = min(1.0, 0.25 + 0.75 * (float(eff_trailing) / denom))
    else:
        trailing_ratio = 0.0

    safe_latency = max(0.0, float(latency_ms))
    latency_norm = min(1.0, math.log1p(safe_latency) / math.log1p(10000.0))

    if socket_closed or not data:
        fin_rst_timeout = 1.0
    elif safe_latency >= 5000.0:
        fin_rst_timeout = 0.5
    else:
        fin_rst_timeout = 0.0

    vec = [
        float(status_1xx_malformed),
        float(status_2xx),
        float(status_3xx),
        float(status_4xx),
        float(status_5xx),
        float(framing_cl),
        float(framing_te),
        float(framing_dual),
        float(framing_eof),
        float(framing_h2),
        float(header_count_norm),
        float(connection_mode),
        float(log_body_size),
        float(trailing_ratio),
        float(latency_norm),
        float(fin_rst_timeout),
        1.0 if canary_matched else 0.0,
        1.0 if diff_diverged else 0.0,
    ]
    return vec


def extract_probe_action_vector(
    raw_probe: bytes,
    *,
    domain: str = "",
    mutator_family: str = "",
    pipeline_step: int = 1,
) -> List[float]:
    """
    Extracts a fixed-length (`ACTION_DIM = 16`) structural probe action vector
    representing HTTP method class, framing/smuggling mutation indicators,
    payload scale, categorical domain/mutator projections, and pipeline step.
    """
    data = bytes(raw_probe) if raw_probe else b""

    method_safe_read = 0.0
    method_body_write = 0.0
    method_tunnel = 0.0
    method_custom = 0.0

    cl_flag = 0.0
    te_flag = 0.0
    obs_fold_flag = 0.0
    chunk_ext_flag = 0.0
    trailers_flag = 0.0
    h2_flag = 0.0
    non_ascii_flag = 0.0

    if data:
        header_block, body_bytes, _ = _split_headers_and_body(data)
        lines = header_block.splitlines()
        first_line = lines[0].strip() if lines else b""

        if first_line:
            method_tok = first_line.split(b" ", 1)[0].upper()
            if method_tok in _SAFE_READ_METHODS:
                method_safe_read = 1.0
            elif method_tok in _BODY_WRITE_METHODS:
                method_body_write = 1.0
            elif method_tok in _TUNNEL_METHODS:
                method_tunnel = 1.0
            else:
                method_custom = 1.0

        if b"PRI * HTTP/2.0" in data[:64] or b"HTTP/2" in first_line.upper() or b"HTTP/3" in first_line.upper():
            h2_flag = 1.0

        cl_count = 0
        for line in lines[1:]:
            if not line:
                continue
            if line[0:1] in (b" ", b"\t"):
                obs_fold_flag = 1.0
            if _WS_BEFORE_COLON_RE.match(line):
                obs_fold_flag = 1.0
            if line.startswith(b":"):
                h2_flag = 1.0
            if b":" in line:
                raw_name, raw_val = line.split(b":", 1)
                name = raw_name.strip().lower()
                val_lower = raw_val.strip().lower()
                if name == b"content-length":
                    cl_count += 1
                elif name == b"transfer-encoding":
                    te_flag = 1.0
                elif name == b"trailer":
                    trailers_flag = 1.0
                elif name == b"upgrade" and (b"h2c" in val_lower or b"h2" in val_lower):
                    h2_flag = 1.0

        if cl_count == 1:
            cl_flag = 0.5
        elif cl_count >= 2:
            cl_flag = 1.0

        if body_bytes:
            if _CHUNK_EXT_RE.search(body_bytes):
                chunk_ext_flag = 1.0
            if _CHUNK_TRAILER_RE.search(body_bytes):
                trailers_flag = 1.0

        for byte_val in data:
            if byte_val >= 0x80 or byte_val < 0x09 or (0x0B <= byte_val <= 0x0C) or (0x0E <= byte_val <= 0x1F) or byte_val == 0x7F:
                non_ascii_flag = 1.0
                break

    log_payload_size = min(1.0, math.log1p(float(len(data))) / math.log1p(65536.0))
    domain_h0, domain_h1 = _stable_hash_features(domain, 2)
    mutator_h0 = _stable_hash_features(mutator_family, 1)[0]
    step_norm = min(1.0, math.log1p(float(max(0, int(pipeline_step)))) / math.log1p(16.0))

    vec = [
        float(method_safe_read),
        float(method_body_write),
        float(method_tunnel),
        float(method_custom),
        float(cl_flag),
        float(te_flag),
        float(obs_fold_flag),
        float(chunk_ext_flag),
        float(trailers_flag),
        float(h2_flag),
        float(non_ascii_flag),
        float(log_payload_size),
        float(domain_h0),
        float(domain_h1),
        float(mutator_h0),
        float(step_norm),
    ]
    return vec


# ---------------------------------------------------------------------------
# Pure-Python linear algebra helpers (for NumPy-free fallback parity)
# ---------------------------------------------------------------------------

def _py_zeros_1d(n: int) -> List[float]:
    return [0.0] * n


def _py_zeros_2d(rows: int, cols: int) -> List[List[float]]:
    return [[0.0] * cols for _ in range(rows)]


def _py_copy_1d(v: Sequence[float]) -> List[float]:
    return [float(x) for x in v]


def _py_copy_2d(m: Sequence[Sequence[float]]) -> List[List[float]]:
    return [[float(x) for x in row] for row in m]


def _py_sigmoid(x: float) -> float:
    xc = max(-40.0, min(40.0, x))
    return 1.0 / (1.0 + math.exp(-xc))


def _py_encoder_forward(
    batch_x: List[List[float]],
    params: Dict[str, Any],
) -> Tuple[List[List[float]], Dict[str, Any]]:
    W1: List[List[float]] = params["W1"]
    b1: List[float] = params["b1"]
    ln_g: List[float] = params["ln_g"]
    ln_b: List[float] = params["ln_b"]
    W2: List[List[float]] = params["W2"]
    b2: List[float] = params["b2"]
    W_skip: List[List[float]] = params["W_skip"]

    B = len(batch_x)
    D_in = len(W1)
    H = len(b1)
    D_z = len(b2)

    u_hat_all: List[List[float]] = []
    inv_std_all: List[float] = []
    ln_out_all: List[List[float]] = []
    sig_all: List[List[float]] = []
    h_all: List[List[float]] = []
    z_all: List[List[float]] = []

    for i in range(B):
        xi = batch_x[i]
        u = [0.0] * H
        for k in range(H):
            acc = b1[k]
            for d in range(D_in):
                acc += xi[d] * W1[d][k]
            u[k] = acc

        mean = sum(u) / float(H)
        var = sum((uk - mean) * (uk - mean) for uk in u) / float(H)
        inv_std = 1.0 / math.sqrt(var + _LAYER_NORM_EPS)

        u_hat = [(uk - mean) * inv_std for uk in u]
        ln_out = [ln_g[k] * u_hat[k] + ln_b[k] for k in range(H)]
        sig = [_py_sigmoid(ln_out[k]) for k in range(H)]
        h = [ln_out[k] * sig[k] for k in range(H)]

        z = [0.0] * D_z
        for j in range(D_z):
            acc = b2[j]
            for k in range(H):
                acc += h[k] * W2[k][j]
            for d in range(D_in):
                acc += xi[d] * W_skip[d][j]
            z[j] = acc

        u_hat_all.append(u_hat)
        inv_std_all.append(inv_std)
        ln_out_all.append(ln_out)
        sig_all.append(sig)
        h_all.append(h)
        z_all.append(z)

    cache = {
        "x": batch_x,
        "u_hat": u_hat_all,
        "inv_std": inv_std_all,
        "ln_out": ln_out_all,
        "sig": sig_all,
        "h": h_all,
    }
    return z_all, cache


def _py_encoder_backward(
    dz: List[List[float]],
    params: Dict[str, Any],
    cache: Dict[str, Any],
) -> Dict[str, Any]:
    W1: List[List[float]] = params["W1"]
    ln_g: List[float] = params["ln_g"]
    W2: List[List[float]] = params["W2"]

    x_all: List[List[float]] = cache["x"]
    u_hat_all: List[List[float]] = cache["u_hat"]
    inv_std_all: List[float] = cache["inv_std"]
    ln_out_all: List[List[float]] = cache["ln_out"]
    sig_all: List[List[float]] = cache["sig"]
    h_all: List[List[float]] = cache["h"]

    B = len(dz)
    D_in = len(W1)
    H = len(ln_g)
    D_z = len(W2[0])

    dW2 = _py_zeros_2d(H, D_z)
    db2 = _py_zeros_1d(D_z)
    dW_skip = _py_zeros_2d(D_in, D_z)
    dln_g = _py_zeros_1d(H)
    dln_b = _py_zeros_1d(H)
    dW1 = _py_zeros_2d(D_in, H)
    db1 = _py_zeros_1d(H)

    inv_H = 1.0 / float(H)

    for i in range(B):
        dzi = dz[i]
        hi = h_all[i]
        ln_outi = ln_out_all[i]
        sigi = sig_all[i]
        u_hati = u_hat_all[i]
        inv_std = inv_std_all[i]
        xi = x_all[i]

        for j in range(D_z):
            dzij = dzi[j]
            db2[j] += dzij
            for k in range(H):
                dW2[k][j] += hi[k] * dzij
            for d in range(D_in):
                dW_skip[d][j] += xi[d] * dzij

        du_hat = [0.0] * H
        for k in range(H):
            dhk = 0.0
            W2k = W2[k]
            for j in range(D_z):
                dhk += dzi[j] * W2k[j]
            s = sigi[k]
            dsilu = s * (1.0 + ln_outi[k] * (1.0 - s))
            dln = dhk * dsilu
            dln_g[k] += dln * u_hati[k]
            dln_b[k] += dln
            du_hat[k] = dln * ln_g[k]

        sum_du_hat = sum(du_hat) * inv_H
        sum_du_hat_u = sum(du_hat[k] * u_hati[k] for k in range(H)) * inv_H

        for k in range(H):
            duk = inv_std * (du_hat[k] - sum_du_hat - u_hati[k] * sum_du_hat_u)
            db1[k] += duk
            for d in range(D_in):
                dW1[d][k] += xi[d] * duk

    return {
        "W1": dW1,
        "b1": db1,
        "ln_g": dln_g,
        "ln_b": dln_b,
        "W2": dW2,
        "b2": db2,
        "W_skip": dW_skip,
    }


def _py_predictor_forward(
    z_t: List[List[float]],
    a_t: List[List[float]],
    params: Dict[str, Any],
) -> Tuple[List[List[float]], Dict[str, Any]]:
    Wp1: List[List[float]] = params["Wp1"]
    bp1: List[float] = params["bp1"]
    Wp2: List[List[float]] = params["Wp2"]
    bp2: List[float] = params["bp2"]

    B = len(z_t)
    D_z = len(z_t[0])
    D_a = len(a_t[0])
    D_in = D_z + D_a
    H = len(bp1)

    v_all: List[List[float]] = []
    p1_all: List[List[float]] = []
    sig_all: List[List[float]] = []
    hp_all: List[List[float]] = []
    z_hat_all: List[List[float]] = []

    for i in range(B):
        vi = z_t[i] + a_t[i]
        p1 = [0.0] * H
        for k in range(H):
            acc = bp1[k]
            for d in range(D_in):
                acc += vi[d] * Wp1[d][k]
            p1[k] = acc
        sig = [_py_sigmoid(p1[k]) for k in range(H)]
        hp = [p1[k] * sig[k] for k in range(H)]
        z_hat = [0.0] * D_z
        zi = z_t[i]
        for j in range(D_z):
            acc = bp2[j] + zi[j]
            for k in range(H):
                acc += hp[k] * Wp2[k][j]
            z_hat[j] = acc

        v_all.append(vi)
        p1_all.append(p1)
        sig_all.append(sig)
        hp_all.append(hp)
        z_hat_all.append(z_hat)

    cache = {"v": v_all, "p1": p1_all, "sig": sig_all, "hp": hp_all, "D_z": D_z}
    return z_hat_all, cache


def _py_predictor_backward(
    dz_hat: List[List[float]],
    params: Dict[str, Any],
    cache: Dict[str, Any],
) -> Tuple[List[List[float]], Dict[str, Any]]:
    Wp1: List[List[float]] = params["Wp1"]
    Wp2: List[List[float]] = params["Wp2"]
    v_all: List[List[float]] = cache["v"]
    p1_all: List[List[float]] = cache["p1"]
    sig_all: List[List[float]] = cache["sig"]
    hp_all: List[List[float]] = cache["hp"]
    D_z: int = cache["D_z"]

    B = len(dz_hat)
    D_in = len(Wp1)
    H = len(Wp2)

    dWp2 = _py_zeros_2d(H, D_z)
    dbp2 = _py_zeros_1d(D_z)
    dWp1 = _py_zeros_2d(D_in, H)
    dbp1 = _py_zeros_1d(H)
    dz_t = _py_zeros_2d(B, D_z)

    for i in range(B):
        dzi = dz_hat[i]
        hpi = hp_all[i]
        p1i = p1_all[i]
        sigi = sig_all[i]
        vi = v_all[i]

        # Residual skip gradient z_hat = z_t + delta_z
        for j in range(D_z):
            dzij = dzi[j]
            dz_t[i][j] = dzij
            dbp2[j] += dzij
            for k in range(H):
                dWp2[k][j] += hpi[k] * dzij

        dp1 = [0.0] * H
        for k in range(H):
            dhpk = 0.0
            Wp2k = Wp2[k]
            for j in range(D_z):
                dhpk += dzi[j] * Wp2k[j]
            s = sigi[k]
            dp1[k] = dhpk * s * (1.0 + p1i[k] * (1.0 - s))
            dbp1[k] += dp1[k]
            for d in range(D_in):
                dWp1[d][k] += vi[d] * dp1[k]

        for j in range(D_z):
            acc = 0.0
            Wp1j = Wp1[j]
            for k in range(H):
                acc += dp1[k] * Wp1j[k]
            dz_t[i][j] += acc

    return dz_t, {"Wp1": dWp1, "bp1": dbp1, "Wp2": dWp2, "bp2": dbp2}


def _py_vicreg_loss_and_grad(
    Z: List[List[float]],
    lambda_var: float,
    lambda_cov: float,
) -> Tuple[float, List[List[float]]]:
    B = len(Z)
    D_z = len(Z[0])
    grad = _py_zeros_2d(B, D_z)
    if B <= 1:
        return 0.0, grad

    inv_B = 1.0 / float(B)
    inv_Dz = 1.0 / float(D_z)
    mean = [sum(Z[i][j] for i in range(B)) * inv_B for j in range(D_z)]
    Zc = [[Z[i][j] - mean[j] for j in range(D_z)] for i in range(B)]

    var_loss = 0.0
    for j in range(D_z):
        v = sum(Zc[i][j] * Zc[i][j] for i in range(B)) * inv_B
        s = math.sqrt(v + _VICREG_VAR_EPS)
        if s < _VICREG_GAMMA:
            var_loss += (_VICREG_GAMMA - s) * inv_Dz
            coeff = -lambda_var * inv_Dz * inv_B / s
            for i in range(B):
                grad[i][j] += coeff * Zc[i][j]

    # Off-diagonal covariance
    inv_Bm1 = 1.0 / float(B - 1)
    C_off = _py_zeros_2d(D_z, D_z)
    cov_loss = 0.0
    for j in range(D_z):
        for k in range(D_z):
            if j == k:
                continue
            c_jk = sum(Zc[i][j] * Zc[i][k] for i in range(B)) * inv_Bm1
            C_off[j][k] = c_jk
            cov_loss += c_jk * c_jk * inv_Dz

    cov_coeff = 4.0 * lambda_cov * inv_Dz * inv_Bm1
    for i in range(B):
        Zci = Zc[i]
        gi = grad[i]
        for j in range(D_z):
            acc = 0.0
            for k in range(D_z):
                if j != k:
                    acc += Zci[k] * C_off[k][j]
            gi[j] += cov_coeff * acc

    return lambda_var * var_loss + lambda_cov * cov_loss, grad


# ---------------------------------------------------------------------------
# NumPy float64 accelerated helpers (identical equations to pure-Python path)
# ---------------------------------------------------------------------------

def _np_sigmoid(x: Any) -> Any:
    xc = np.clip(x, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-xc))


def _np_encoder_forward(batch_x: Any, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
    u = batch_x @ params["W1"] + params["b1"]
    mean = np.mean(u, axis=1, keepdims=True)
    var = np.mean((u - mean) ** 2, axis=1, keepdims=True)
    inv_std = 1.0 / np.sqrt(var + _LAYER_NORM_EPS)
    u_hat = (u - mean) * inv_std
    ln_out = u_hat * params["ln_g"] + params["ln_b"]
    sig = _np_sigmoid(ln_out)
    h = ln_out * sig
    z = h @ params["W2"] + params["b2"] + batch_x @ params["W_skip"]
    cache = {
        "x": batch_x,
        "u_hat": u_hat,
        "inv_std": inv_std,
        "ln_out": ln_out,
        "sig": sig,
        "h": h,
    }
    return z, cache


def _np_encoder_backward(dz: Any, params: Dict[str, Any], cache: Dict[str, Any]) -> Dict[str, Any]:
    h = cache["h"]
    ln_out = cache["ln_out"]
    sig = cache["sig"]
    u_hat = cache["u_hat"]
    inv_std = cache["inv_std"]
    x = cache["x"]

    dW2 = h.T @ dz
    db2 = np.sum(dz, axis=0)
    dW_skip = x.T @ dz

    dh = dz @ params["W2"].T
    dsilu = sig * (1.0 + ln_out * (1.0 - sig))
    dln = dh * dsilu

    dln_g = np.sum(dln * u_hat, axis=0)
    dln_b = np.sum(dln, axis=0)

    du_hat = dln * params["ln_g"]
    du = inv_std * (
        du_hat
        - np.mean(du_hat, axis=1, keepdims=True)
        - u_hat * np.mean(du_hat * u_hat, axis=1, keepdims=True)
    )

    dW1 = x.T @ du
    db1 = np.sum(du, axis=0)
    return {
        "W1": dW1,
        "b1": db1,
        "ln_g": dln_g,
        "ln_b": dln_b,
        "W2": dW2,
        "b2": db2,
        "W_skip": dW_skip,
    }


def _np_predictor_forward(z_t: Any, a_t: Any, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
    v = np.concatenate([z_t, a_t], axis=1)
    p1 = v @ params["Wp1"] + params["bp1"]
    sig = _np_sigmoid(p1)
    hp = p1 * sig
    z_hat = z_t + hp @ params["Wp2"] + params["bp2"]
    cache = {"v": v, "p1": p1, "sig": sig, "hp": hp, "D_z": z_t.shape[1]}
    return z_hat, cache


def _np_predictor_backward(dz_hat: Any, params: Dict[str, Any], cache: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
    v = cache["v"]
    p1 = cache["p1"]
    sig = cache["sig"]
    hp = cache["hp"]
    D_z = cache["D_z"]

    dWp2 = hp.T @ dz_hat
    dbp2 = np.sum(dz_hat, axis=0)

    dhp = dz_hat @ params["Wp2"].T
    dp1 = dhp * (sig * (1.0 + p1 * (1.0 - sig)))

    dWp1 = v.T @ dp1
    dbp1 = np.sum(dp1, axis=0)

    dv = dp1 @ params["Wp1"].T
    dz_t = dz_hat + dv[:, :D_z]
    return dz_t, {"Wp1": dWp1, "bp1": dbp1, "Wp2": dWp2, "bp2": dbp2}


def _np_vicreg_loss_and_grad(Z: Any, lambda_var: float, lambda_cov: float) -> Tuple[float, Any]:
    B, D_z = Z.shape
    if B <= 1:
        return 0.0, np.zeros_like(Z)

    mean = np.mean(Z, axis=0, keepdims=True)
    Zc = Z - mean

    var = np.mean(Zc * Zc, axis=0)
    std = np.sqrt(var + _VICREG_VAR_EPS)
    hinge = np.maximum(0.0, _VICREG_GAMMA - std)
    var_loss = float(np.mean(hinge))

    active = (std < _VICREG_GAMMA).astype(np.float64)
    grad_var = (-lambda_var / (float(D_z) * float(B))) * (Zc * (active / std))

    C = (Zc.T @ Zc) / float(B - 1)
    C_off = C.copy()
    np.fill_diagonal(C_off, 0.0)
    cov_loss = float(np.sum(C_off * C_off) / float(D_z))
    grad_cov = (4.0 * lambda_cov / (float(D_z) * float(B - 1))) * (Zc @ C_off)

    return lambda_var * var_loss + lambda_cov * cov_loss, grad_var + grad_cov


# ---------------------------------------------------------------------------
# Main JEPA World Model & Calibrated Surprise Sensor
# ---------------------------------------------------------------------------

class LatentProtocolJEPA:
    """
    Collapse-free Joint Embedding Predictive Architecture (JEPA) for protocol
    transition dynamics and calibrated latent anomaly detection.
    """

    def __init__(
        self,
        state_dim: int = STATE_DIM,
        action_dim: int = ACTION_DIM,
        latent_dim: int = 8,
        hidden_dim: int = 24,
        *,
        ema_decay: float = 0.99,
        min_benign_transitions: int = 200,
        quantile: float = 0.99,
        stack_profile: str = "generic",
        seed: int = 42,
    ) -> None:
        if state_dim <= 0 or action_dim <= 0 or latent_dim <= 0 or hidden_dim <= 0:
            raise ValueError("Dimensions must be positive integers.")
        if not (0.0 < ema_decay < 1.0):
            raise ValueError("ema_decay must lie strictly in (0, 1).")
        if min_benign_transitions < 1:
            raise ValueError("min_benign_transitions must be >= 1.")
        if not (0.5 <= quantile < 1.0):
            raise ValueError("quantile must lie in [0.5, 1.0).")

        self.state_dim = int(state_dim)
        self.action_dim = int(action_dim)
        self.latent_dim = int(latent_dim)
        self.hidden_dim = int(hidden_dim)
        self.ema_decay = float(ema_decay)
        self.min_benign_transitions = int(min_benign_transitions)
        self.quantile = float(quantile)
        self.stack_profile = str(stack_profile or "generic")
        self.seed = int(seed)

        self._backend_label: str = "latent_jepa_world_model"
        self._use_numpy: bool = bool(_HAS_NUMPY and np is not None)
        self._calibrated: bool = False
        self._threshold: float = float("inf")
        self._benign_shift_threshold: float = 1.0
        self._trained_transitions: int = 0

        self._state_mean: List[float] = [0.0] * self.state_dim
        self._state_scale: List[float] = [1.0] * self.state_dim
        self._action_mean: List[float] = [0.0] * self.action_dim
        self._action_scale: List[float] = [1.0] * self.action_dim
        self._target_latent_mean: List[float] = [0.0] * self.latent_dim

        self._online_params: Dict[str, Any] = {}
        self._target_params: Dict[str, Any] = {}
        self._pred_params: Dict[str, Any] = {}
        self._init_parameters()

    @property
    def calibrated(self) -> bool:
        return self._calibrated

    @property
    def threshold(self) -> float:
        return self._threshold

    @property
    def trained_transitions(self) -> int:
        return self._trained_transitions

    @property
    def backend_label(self) -> str:
        return self._backend_label

    def _init_parameters(self) -> None:
        """Deterministic seeded initialization identical across NumPy and pure Python."""
        rng = random.Random(self.seed)

        def _rand_matrix(rows: int, cols: int, scale_mult: float = 1.0) -> List[List[float]]:
            std = scale_mult * math.sqrt(2.0 / float(rows + cols))
            return [[rng.gauss(0.0, std) for _ in range(cols)] for _ in range(rows)]

        online_py: Dict[str, Any] = {
            "W1": _rand_matrix(self.state_dim, self.hidden_dim),
            "b1": _py_zeros_1d(self.hidden_dim),
            "ln_g": [1.0] * self.hidden_dim,
            "ln_b": _py_zeros_1d(self.hidden_dim),
            "W2": _rand_matrix(self.hidden_dim, self.latent_dim),
            "b2": _py_zeros_1d(self.latent_dim),
            "W_skip": _rand_matrix(self.state_dim, self.latent_dim, scale_mult=0.5),
        }
        target_py: Dict[str, Any] = {
            "W1": _py_copy_2d(online_py["W1"]),
            "b1": _py_copy_1d(online_py["b1"]),
            "ln_g": _py_copy_1d(online_py["ln_g"]),
            "ln_b": _py_copy_1d(online_py["ln_b"]),
            "W2": _py_copy_2d(online_py["W2"]),
            "b2": _py_copy_1d(online_py["b2"]),
            "W_skip": _py_copy_2d(online_py["W_skip"]),
        }
        pred_py: Dict[str, Any] = {
            "Wp1": _rand_matrix(self.latent_dim + self.action_dim, self.hidden_dim),
            "bp1": _py_zeros_1d(self.hidden_dim),
            "Wp2": _rand_matrix(self.hidden_dim, self.latent_dim, scale_mult=0.5),
            "bp2": _py_zeros_1d(self.latent_dim),
        }

        if self._use_numpy:
            self._online_params = {k: np.array(v, dtype=np.float64) for k, v in online_py.items()}
            self._target_params = {k: np.array(v, dtype=np.float64) for k, v in target_py.items()}
            self._pred_params = {k: np.array(v, dtype=np.float64) for k, v in pred_py.items()}
        else:
            self._online_params = online_py
            self._target_params = target_py
            self._pred_params = pred_py

    def _validate_vector(self, vec: Sequence[float], expected_dim: int, name: str) -> List[float]:
        if len(vec) != expected_dim:
            raise ValueError(f"Expected {name} of length {expected_dim}, got {len(vec)}.")
        out: List[float] = []
        for val in vec:
            fv = float(val)
            if not math.isfinite(fv):
                raise ValueError(f"Non-finite value in {name}: {val!r}")
            out.append(fv)
        return out

    def _normalize_state(self, state: Sequence[float]) -> List[float]:
        s = self._validate_vector(state, self.state_dim, "state")
        return [(s[i] - self._state_mean[i]) / self._state_scale[i] for i in range(self.state_dim)]

    def _normalize_action(self, action: Sequence[float]) -> List[float]:
        a = self._validate_vector(action, self.action_dim, "probe_action")
        return [(a[i] - self._action_mean[i]) / self._action_scale[i] for i in range(self.action_dim)]

    def _fit_normalizers(
        self,
        train_transitions: Sequence[Tuple[List[float], List[float], List[float]]],
    ) -> None:
        all_states: List[List[float]] = []
        all_actions: List[List[float]] = []
        for s_prev, act, s_next in train_transitions:
            all_states.append(s_prev)
            all_states.append(s_next)
            all_actions.append(act)

        n_s = float(len(all_states))
        s_mean = [sum(row[d] for row in all_states) / n_s for d in range(self.state_dim)]
        s_scale: List[float] = []
        for d in range(self.state_dim):
            var = sum((row[d] - s_mean[d]) ** 2 for row in all_states) / n_s
            s_scale.append(max(math.sqrt(var), _MIN_STATE_SCALE))

        n_a = float(len(all_actions))
        a_mean = [sum(row[d] for row in all_actions) / n_a for d in range(self.action_dim)]
        a_scale: List[float] = []
        for d in range(self.action_dim):
            var = sum((row[d] - a_mean[d]) ** 2 for row in all_actions) / n_a
            a_scale.append(max(math.sqrt(var), _MIN_ACTION_SCALE))

        self._state_mean = s_mean
        self._state_scale = s_scale
        self._action_mean = a_mean
        self._action_scale = a_scale

    def encode_online(self, state: Sequence[float]) -> List[float]:
        """Encodes a protocol state vector using the online encoder E_theta."""
        xn = self._normalize_state(state)
        if self._use_numpy:
            z, _ = _np_encoder_forward(np.asarray([xn], dtype=np.float64), self._online_params)
            return [float(v) for v in z[0].tolist()]
        z_py, _ = _py_encoder_forward([xn], self._online_params)
        return list(z_py[0])

    def encode_target(self, state: Sequence[float]) -> List[float]:
        """Encodes a protocol state vector using the stop-gradient EMA target encoder."""
        xn = self._normalize_state(state)
        if self._use_numpy:
            z, _ = _np_encoder_forward(np.asarray([xn], dtype=np.float64), self._target_params)
            return [float(v) for v in z[0].tolist()]
        z_py, _ = _py_encoder_forward([xn], self._target_params)
        return list(z_py[0])

    def predict_next_latent(
        self,
        z_t: Sequence[float],
        probe_action: Sequence[float],
    ) -> List[float]:
        """Predicts next target latent z_hat_{t+1} from (z_t, probe_action)."""
        z_vec = self._validate_vector(z_t, self.latent_dim, "z_t")
        a_norm = self._normalize_action(probe_action)
        if self._use_numpy:
            z_hat, _ = _np_predictor_forward(
                np.asarray([z_vec], dtype=np.float64),
                np.asarray([a_norm], dtype=np.float64),
                self._pred_params,
            )
            return [float(v) for v in z_hat[0].tolist()]
        z_hat_py, _ = _py_predictor_forward([z_vec], [a_norm], self._pred_params)
        return list(z_hat_py[0])

    def embedding_statistics(
        self,
        states: Sequence[Sequence[float]],
        *,
        use_target_encoder: bool = False,
    ) -> Dict[str, Any]:
        """Computes per-dimension std and off-diagonal covariance to verify non-collapse."""
        if not states:
            return {
                "count": 0,
                "per_dim_std": [0.0] * self.latent_dim,
                "min_std": 0.0,
                "mean_std": 0.0,
                "off_diagonal_cov": 0.0,
            }
        norm_states = [self._normalize_state(s) for s in states]
        params = self._target_params if use_target_encoder else self._online_params
        if self._use_numpy:
            Z, _ = _np_encoder_forward(np.asarray(norm_states, dtype=np.float64), params)
            Z_list = Z.tolist()
        else:
            Z_list, _ = _py_encoder_forward(norm_states, params)

        n = len(Z_list)
        D = self.latent_dim
        mean = [sum(Z_list[i][j] for i in range(n)) / float(n) for j in range(D)]
        Zc = [[Z_list[i][j] - mean[j] for j in range(D)] for i in range(n)]
        stds = [math.sqrt(sum(Zc[i][j] ** 2 for i in range(n)) / float(n)) for j in range(D)]

        off_diag_sq = 0.0
        if n > 1 and D > 1:
            inv_nm1 = 1.0 / float(n - 1)
            for j in range(D):
                for k in range(D):
                    if j == k:
                        continue
                    c_jk = sum(Zc[i][j] * Zc[i][k] for i in range(n)) * inv_nm1
                    off_diag_sq += c_jk * c_jk
            off_diag_cov = off_diag_sq / float(D * (D - 1))
        else:
            off_diag_cov = 0.0

        return {
            "count": n,
            "per_dim_std": [float(s) for s in stds],
            "min_std": float(min(stds)),
            "mean_std": float(sum(stds) / float(D)),
            "off_diagonal_cov": float(off_diag_cov),
        }

    def _batch_train_step_np(
        self,
        bx_prev: Any,
        ba: Any,
        bx_next: Any,
        lr: float,
        adam_state: Dict[str, Any],
    ) -> float:
        B = bx_prev.shape[0]
        D_z = self.latent_dim

        z_prev, cache_prev = _np_encoder_forward(bx_prev, self._online_params)
        z_next_online, cache_next = _np_encoder_forward(bx_next, self._online_params)
        # Strict stop-gradient target encoder
        z_next_target, _ = _np_encoder_forward(bx_next, self._target_params)
        z_hat, cache_pred = _np_predictor_forward(z_prev, ba, self._pred_params)

        diff = z_hat - z_next_target
        pred_loss = float(np.mean(np.sum(diff * diff, axis=1)))
        dz_hat = (2.0 / float(B)) * diff

        z_pooled = np.concatenate([z_prev, z_next_online], axis=0)
        vic_loss, grad_vic_pooled = _np_vicreg_loss_and_grad(z_pooled, _LAMBDA_VAR, _LAMBDA_COV)
        grad_vic_prev = grad_vic_pooled[:B]
        grad_vic_next = grad_vic_pooled[B:]
        total_loss = pred_loss + vic_loss

        dz_prev_from_pred, pred_grads = _np_predictor_backward(dz_hat, self._pred_params, cache_pred)
        dz_prev_total = dz_prev_from_pred + grad_vic_prev
        enc_grads_prev = _np_encoder_backward(dz_prev_total, self._online_params, cache_prev)
        enc_grads_next = _np_encoder_backward(grad_vic_next, self._online_params, cache_next)

        enc_grads = {k: enc_grads_prev[k] + enc_grads_next[k] for k in self._online_params}

        # Global gradient clipping
        sq_norm = 0.0
        for g in enc_grads.values():
            sq_norm += float(np.sum(g * g))
        for g in pred_grads.values():
            sq_norm += float(np.sum(g * g))
        grad_norm = math.sqrt(sq_norm)
        clip_scale = (_MAX_GRAD_NORM / grad_norm) if grad_norm > _MAX_GRAD_NORM else 1.0

        adam_state["step"] += 1
        t = adam_state["step"]
        beta1, beta2, eps = 0.9, 0.999, 1e-8
        bc1 = 1.0 - (beta1 ** t)
        bc2 = 1.0 - (beta2 ** t)

        def _adam_update(prefix: str, params: Dict[str, Any], grads: Dict[str, Any]) -> None:
            for name, param in params.items():
                g = grads[name] * clip_scale
                key = f"{prefix}.{name}"
                m = adam_state["m"][key]
                v = adam_state["v"][key]
                m[:] = beta1 * m + (1.0 - beta1) * g
                v[:] = beta2 * v + (1.0 - beta2) * (g * g)
                m_hat = m / bc1
                v_hat = v / bc2
                if name.startswith("W"):
                    param *= 1.0 - lr * _WEIGHT_DECAY
                param -= lr * m_hat / (np.sqrt(v_hat) + eps)

        _adam_update("enc", self._online_params, enc_grads)
        _adam_update("pred", self._pred_params, pred_grads)

        # EMA Target Encoder update: bar_theta <- tau * bar_theta + (1 - tau) * theta
        tau = self.ema_decay
        one_minus_tau = 1.0 - tau
        for name in self._target_params:
            self._target_params[name][:] = (
                tau * self._target_params[name] + one_minus_tau * self._online_params[name]
            )

        return total_loss

    def _batch_train_step_py(
        self,
        bx_prev: List[List[float]],
        ba: List[List[float]],
        bx_next: List[List[float]],
        lr: float,
        adam_state: Dict[str, Any],
    ) -> float:
        B = len(bx_prev)
        D_z = self.latent_dim

        z_prev, cache_prev = _py_encoder_forward(bx_prev, self._online_params)
        z_next_online, cache_next = _py_encoder_forward(bx_next, self._online_params)
        # Strict stop-gradient target encoder
        z_next_target, _ = _py_encoder_forward(bx_next, self._target_params)
        z_hat, cache_pred = _py_predictor_forward(z_prev, ba, self._pred_params)

        inv_B = 1.0 / float(B)
        pred_sq = 0.0
        dz_hat = _py_zeros_2d(B, D_z)
        for i in range(B):
            for j in range(D_z):
                d = z_hat[i][j] - z_next_target[i][j]
                pred_sq += d * d
                dz_hat[i][j] = 2.0 * inv_B * d
        pred_loss = pred_sq * inv_B

        z_pooled = z_prev + z_next_online
        vic_loss, grad_vic_pooled = _py_vicreg_loss_and_grad(z_pooled, _LAMBDA_VAR, _LAMBDA_COV)
        grad_vic_prev = grad_vic_pooled[:B]
        grad_vic_next = grad_vic_pooled[B:]
        total_loss = pred_loss + vic_loss

        dz_prev_from_pred, pred_grads = _py_predictor_backward(dz_hat, self._pred_params, cache_pred)
        dz_prev_total = [
            [dz_prev_from_pred[i][j] + grad_vic_prev[i][j] for j in range(D_z)]
            for i in range(B)
        ]

        enc_grads_prev = _py_encoder_backward(dz_prev_total, self._online_params, cache_prev)
        enc_grads_next = _py_encoder_backward(grad_vic_next, self._online_params, cache_next)

        enc_grads: Dict[str, Any] = {}
        for k in self._online_params:
            gp = enc_grads_prev[k]
            gn = enc_grads_next[k]
            if isinstance(gp[0], list):
                enc_grads[k] = [
                    [gp[r][c] + gn[r][c] for c in range(len(gp[0]))]
                    for r in range(len(gp))
                ]
            else:
                enc_grads[k] = [gp[c] + gn[c] for c in range(len(gp))]

        sq_norm = 0.0
        for gdict in (enc_grads, pred_grads):
            for g in gdict.values():
                if isinstance(g[0], list):
                    for row in g:
                        for v in row:
                            sq_norm += v * v
                else:
                    for v in g:
                        sq_norm += v * v
        grad_norm = math.sqrt(sq_norm)
        clip_scale = (_MAX_GRAD_NORM / grad_norm) if grad_norm > _MAX_GRAD_NORM else 1.0

        adam_state["step"] += 1
        t = adam_state["step"]
        beta1, beta2, eps = 0.9, 0.999, 1e-8
        bc1 = 1.0 - (beta1 ** t)
        bc2 = 1.0 - (beta2 ** t)

        def _adam_update_py(prefix: str, params: Dict[str, Any], grads: Dict[str, Any]) -> None:
            decay_factor = 1.0 - lr * _WEIGHT_DECAY
            for name, param in params.items():
                g = grads[name]
                key = f"{prefix}.{name}"
                m = adam_state["m"][key]
                v = adam_state["v"][key]
                is_w = name.startswith("W")
                if isinstance(param[0], list):
                    for r in range(len(param)):
                        pr = param[r]
                        gr = g[r]
                        mr = m[r]
                        vr = v[r]
                        for c in range(len(pr)):
                            gv = gr[c] * clip_scale
                            mr[c] = beta1 * mr[c] + (1.0 - beta1) * gv
                            vr[c] = beta2 * vr[c] + (1.0 - beta2) * (gv * gv)
                            if is_w:
                                pr[c] *= decay_factor
                            pr[c] -= lr * (mr[c] / bc1) / (math.sqrt(vr[c] / bc2) + eps)
                else:
                    for c in range(len(param)):
                        gv = g[c] * clip_scale
                        m[c] = beta1 * m[c] + (1.0 - beta1) * gv
                        v[c] = beta2 * v[c] + (1.0 - beta2) * (gv * gv)
                        if is_w:
                            param[c] *= decay_factor
                        param[c] -= lr * (m[c] / bc1) / (math.sqrt(v[c] / bc2) + eps)

        _adam_update_py("enc", self._online_params, enc_grads)
        _adam_update_py("pred", self._pred_params, pred_grads)

        # EMA Target Encoder update
        tau = self.ema_decay
        one_minus_tau = 1.0 - tau
        for name, tparam in self._target_params.items():
            oparam = self._online_params[name]
            if isinstance(tparam[0], list):
                for r in range(len(tparam)):
                    tr = tparam[r]
                    orr = oparam[r]
                    for c in range(len(tr)):
                        tr[c] = tau * tr[c] + one_minus_tau * orr[c]
            else:
                for c in range(len(tparam)):
                    tparam[c] = tau * tparam[c] + one_minus_tau * oparam[c]

        return total_loss

    def _init_adam_state(self) -> Dict[str, Any]:
        m: Dict[str, Any] = {}
        v: Dict[str, Any] = {}
        for prefix, pdict in (("enc", self._online_params), ("pred", self._pred_params)):
            for name, param in pdict.items():
                key = f"{prefix}.{name}"
                if self._use_numpy:
                    m[key] = np.zeros_like(param)
                    v[key] = np.zeros_like(param)
                else:
                    if isinstance(param[0], list):
                        m[key] = _py_zeros_2d(len(param), len(param[0]))
                        v[key] = _py_zeros_2d(len(param), len(param[0]))
                    else:
                        m[key] = _py_zeros_1d(len(param))
                        v[key] = _py_zeros_1d(len(param))
        return {"step": 0, "m": m, "v": v}

    def fit_and_calibrate(
        self,
        transitions: Sequence[Tuple[Sequence[float], Sequence[float], Sequence[float]]],
        *,
        epochs: int = 25,
        lr: float = 0.01,
        val_ratio: float = 0.25,
    ) -> Dict[str, Any]:
        """
        Trains the online encoder + forward predictor with EMA target encoder
        and VICReg anti-collapse regularization, then calibrates the empirical
        split-conformal surprise threshold on the held-out calibration split.

        Enforces the real-data cold-start safety gate: if fewer than
        `self.min_benign_transitions` transitions are provided, the model stays
        uncalibrated (`calibrated=False`).
        """
        n_total = len(transitions)
        if n_total < self.min_benign_transitions:
            self._calibrated = False
            self._threshold = float("inf")
            self._trained_transitions = 0
            return {
                "calibrated": False,
                "reason": "insufficient_real_transitions",
                "count": n_total,
                "required": self.min_benign_transitions,
            }

        validated: List[Tuple[List[float], List[float], List[float]]] = []
        for idx, item in enumerate(transitions):
            if len(item) != 3:
                raise ValueError(f"Transition #{idx} must be a 3-tuple (prev_state, action, next_state).")
            s_prev = self._validate_vector(item[0], self.state_dim, "prev_state")
            act = self._validate_vector(item[1], self.action_dim, "probe_action")
            s_next = self._validate_vector(item[2], self.state_dim, "next_state")
            validated.append((s_prev, act, s_next))

        # Fresh deterministic initialization for reproducible training
        self._init_parameters()

        rng = random.Random(self.seed)
        indices = list(range(n_total))
        rng.shuffle(indices)

        clamped_val_ratio = max(0.1, min(0.5, float(val_ratio)))
        n_val = max(1, min(n_total - 1, int(round(n_total * clamped_val_ratio))))
        val_indices = indices[:n_val]
        train_indices = indices[n_val:]

        train_raw = [validated[i] for i in train_indices]
        val_raw = [validated[i] for i in val_indices]

        # Fit feature normalizers strictly on the training split (zero leakage)
        self._fit_normalizers(train_raw)

        train_prev_norm = [self._normalize_state(t[0]) for t in train_raw]
        train_act_norm = [self._normalize_action(t[1]) for t in train_raw]
        train_next_norm = [self._normalize_state(t[2]) for t in train_raw]

        n_train = len(train_raw)
        batch_size = min(32, max(8, n_train // 4)) if n_train >= 8 else n_train
        adam_state = self._init_adam_state()

        if self._use_numpy:
            X_prev_all = np.asarray(train_prev_norm, dtype=np.float64)
            A_all = np.asarray(train_act_norm, dtype=np.float64)
            X_next_all = np.asarray(train_next_norm, dtype=np.float64)

        final_loss = 0.0
        n_epochs = max(1, int(epochs))
        step_lr = float(lr)

        for _ in range(n_epochs):
            order = list(range(n_train))
            rng.shuffle(order)
            epoch_loss = 0.0
            n_batches = 0
            for start in range(0, n_train, batch_size):
                b_idx = order[start : start + batch_size]
                if len(b_idx) < 2 and n_train >= 2:
                    continue
                if self._use_numpy:
                    loss = self._batch_train_step_np(
                        X_prev_all[b_idx],
                        A_all[b_idx],
                        X_next_all[b_idx],
                        step_lr,
                        adam_state,
                    )
                else:
                    loss = self._batch_train_step_py(
                        [train_prev_norm[i] for i in b_idx],
                        [train_act_norm[i] for i in b_idx],
                        [train_next_norm[i] for i in b_idx],
                        step_lr,
                        adam_state,
                    )
                epoch_loss += loss
                n_batches += 1
            if n_batches > 0:
                final_loss = epoch_loss / float(n_batches)

        # Compute benign target latent centroid on training split (for prior-free probe scoring)
        train_next_latents: List[List[float]] = []
        if self._use_numpy:
            z_tr, _ = _np_encoder_forward(X_next_all, self._target_params)
            self._target_latent_mean = [float(v) for v in np.mean(z_tr, axis=0).tolist()]
        else:
            train_next_latents, _ = _py_encoder_forward(train_next_norm, self._target_params)
            self._target_latent_mean = [
                sum(row[j] for row in train_next_latents) / float(len(train_next_latents))
                for j in range(self.latent_dim)
            ]

        # Held-out split-conformal quantile calibration
        val_scores: List[float] = []
        val_shifts: List[float] = []
        for s_prev, act, s_next in val_raw:
            z_p = self.encode_online(s_prev)
            z_hat = self.predict_next_latent(z_p, act)
            z_tgt = self.encode_target(s_next)
            s_score = sum((z_hat[j] - z_tgt[j]) ** 2 for j in range(self.latent_dim))
            val_scores.append(float(s_score))

            shift = sum((z_hat[j] - self._target_latent_mean[j]) ** 2 for j in range(self.latent_dim))
            val_shifts.append(float(shift))

        sorted_scores = sorted(val_scores)
        nv = len(sorted_scores)
        conformal_rank = int(math.ceil((nv + 1) * self.quantile))
        q_idx = min(nv - 1, max(0, conformal_rank - 1))
        q_emp = sorted_scores[q_idx]

        val_mean = sum(sorted_scores) / float(nv)
        val_var = sum((x - val_mean) ** 2 for x in sorted_scores) / float(nv)
        val_std = math.sqrt(val_var)

        val_next_states = [t[2] for t in val_raw]
        emb_stats = self.embedding_statistics(val_next_states, use_target_encoder=True)
        latent_energy = sum(s * s for s in emb_stats["per_dim_std"])

        # Finite-sample split-conformal safety margin scaled to validation spread & latent energy
        conformal_margin = max(
            1e-4,
            0.015 * latent_energy,
            (1.0 / float(nv + 1)) * max(q_emp, val_std, 1e-3) + 0.5 * val_std,
        )
        self._threshold = float(q_emp + conformal_margin)

        sorted_shifts = sorted(val_shifts)
        shift_q = sorted_shifts[q_idx]
        shift_mean = sum(sorted_shifts) / float(nv)
        shift_std = math.sqrt(sum((x - shift_mean) ** 2 for x in sorted_shifts) / float(nv))
        self._benign_shift_threshold = float(max(1e-3, shift_q + 0.25 * shift_std + 0.05))

        self._calibrated = True
        self._trained_transitions = n_total

        return {
            "calibrated": True,
            "count": n_total,
            "train_count": n_train,
            "val_count": nv,
            "threshold": self._threshold,
            "quantile": self.quantile,
            "val_mean_surprise": float(val_mean),
            "val_p99_surprise": float(q_emp),
            "conformal_margin": float(conformal_margin),
            "embedding_min_std": emb_stats["min_std"],
            "embedding_mean_std": emb_stats["mean_std"],
            "embedding_offdiag_cov": emb_stats["off_diagonal_cov"],
            "final_loss": float(final_loss),
            "stack_profile": self.stack_profile,
            "backend_label": self.backend_label,
            "math_backend": "numpy" if self._use_numpy else "python",
        }

    def score_transition(
        self,
        prev_state: Sequence[float],
        probe_action: Sequence[float],
        next_state: Sequence[float],
    ) -> LatentSurpriseVerdict:
        """
        Scores a single (prev_state, probe_action, next_state) transition in latent
        space using the calibrated EMA-JEPA world model.

        Fail-closed under cold start: returns `is_anomalous=False, calibrated=False`
        whenever the model has not passed the real-data calibration gate.
        """
        z_t = self.encode_online(prev_state)
        z_hat = self.predict_next_latent(z_t, probe_action)
        z_target = self.encode_target(next_state)

        surprise = float(sum((z_hat[j] - z_target[j]) ** 2 for j in range(self.latent_dim)))

        if not self._calibrated:
            return LatentSurpriseVerdict(
                surprise_score=surprise,
                threshold=float(self._threshold),
                is_anomalous=False,
                calibrated=False,
                stack_profile=self.stack_profile,
                backend_label=self._backend_label,
                reason="model_uncalibrated_cold_start",
            )

        is_anom = bool(surprise > self._threshold)
        q_pct = int(round(self.quantile * 100.0))
        reason = (
            f"latent_surprise_exceeded_p{q_pct}"
            if is_anom
            else "within_calibrated_manifold"
        )
        return LatentSurpriseVerdict(
            surprise_score=surprise,
            threshold=float(self._threshold),
            is_anomalous=is_anom,
            calibrated=True,
            stack_profile=self.stack_profile,
            backend_label=self._backend_label,
            reason=reason,
        )

    def predict_anomaly_score(
        self,
        raw_probe: bytes,
        *,
        baseline_response: bytes = b"",
        domain: str = "",
        mutator_family: str = "",
    ) -> Optional[float]:
        """
        Predicts a calibrated anomaly risk score in [0.0, 1.0] for a candidate
        probe prior to network execution (used by `ProtocolWorldModel`).

        Returns `None` while uncalibrated so callers stay fail-closed.
        """
        if not self._calibrated:
            return None

        if baseline_response:
            prev_state = extract_response_state_vector(baseline_response)
            z_ref = self.encode_target(prev_state)
        else:
            prev_state = list(self._state_mean)
            z_ref = list(self._target_latent_mean)

        action_vec = extract_probe_action_vector(
            raw_probe,
            domain=domain,
            mutator_family=mutator_family,
        )
        z_t = self.encode_online(prev_state)
        z_hat = self.predict_next_latent(z_t, action_vec)

        latent_shift = sum((z_hat[j] - z_ref[j]) ** 2 for j in range(self.latent_dim))

        # Out-of-manifold normalized action excursion (captures novel framing mutations)
        a_norm = self._normalize_action(action_vec)
        action_ood = sum(v * v for v in a_norm) / float(self.action_dim)

        combined = latent_shift + 0.5 * action_ood
        ratio = combined / max(self._benign_shift_threshold, 1e-4)
        score = ratio / (1.0 + ratio)
        return float(max(0.0, min(1.0, score)))

    def _params_to_plain(self, params: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in params.items():
            if self._use_numpy:
                out[k] = v.tolist()
            elif isinstance(v[0], list):
                out[k] = _py_copy_2d(v)
            else:
                out[k] = _py_copy_1d(v)
        return out

    def to_dict(self) -> Dict[str, Any]:
        """Serializes weights, normalizers, and calibration metadata to JSON-safe dict."""
        return {
            "version": 1,
            "state_dim": self.state_dim,
            "action_dim": self.action_dim,
            "latent_dim": self.latent_dim,
            "hidden_dim": self.hidden_dim,
            "ema_decay": self.ema_decay,
            "min_benign_transitions": self.min_benign_transitions,
            "quantile": self.quantile,
            "stack_profile": self.stack_profile,
            "seed": self.seed,
            "backend_label": self._backend_label,
            "calibrated": self._calibrated,
            "threshold": None if not math.isfinite(self._threshold) else float(self._threshold),
            "benign_shift_threshold": float(self._benign_shift_threshold),
            "trained_transitions": self._trained_transitions,
            "state_mean": [float(v) for v in self._state_mean],
            "state_scale": [float(v) for v in self._state_scale],
            "action_mean": [float(v) for v in self._action_mean],
            "action_scale": [float(v) for v in self._action_scale],
            "target_latent_mean": [float(v) for v in self._target_latent_mean],
            "online_encoder": self._params_to_plain(self._online_params),
            "target_encoder": self._params_to_plain(self._target_params),
            "predictor": self._params_to_plain(self._pred_params),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LatentProtocolJEPA":
        """Reconstructs a `LatentProtocolJEPA` instance from `to_dict()` output."""
        if not isinstance(data, dict):
            raise ValueError("Serialized JEPA payload must be a dict.")

        model = cls(
            state_dim=int(data.get("state_dim", STATE_DIM)),
            action_dim=int(data.get("action_dim", ACTION_DIM)),
            latent_dim=int(data.get("latent_dim", 8)),
            hidden_dim=int(data.get("hidden_dim", 24)),
            ema_decay=float(data.get("ema_decay", 0.99)),
            min_benign_transitions=int(data.get("min_benign_transitions", 200)),
            quantile=float(data.get("quantile", 0.99)),
            stack_profile=str(data.get("stack_profile", "generic")),
            seed=int(data.get("seed", 42)),
        )
        model._backend_label = str(data.get("backend_label", "latent_jepa_world_model"))
        model._calibrated = bool(data.get("calibrated", False))
        raw_thresh = data.get("threshold")
        model._threshold = float("inf") if raw_thresh is None else float(raw_thresh)
        model._benign_shift_threshold = float(data.get("benign_shift_threshold", 1.0))
        model._trained_transitions = int(data.get("trained_transitions", 0))

        model._state_mean = model._validate_vector(
            data.get("state_mean", [0.0] * model.state_dim), model.state_dim, "state_mean"
        )
        model._state_scale = model._validate_vector(
            data.get("state_scale", [1.0] * model.state_dim), model.state_dim, "state_scale"
        )
        model._action_mean = model._validate_vector(
            data.get("action_mean", [0.0] * model.action_dim), model.action_dim, "action_mean"
        )
        model._action_scale = model._validate_vector(
            data.get("action_scale", [1.0] * model.action_dim), model.action_dim, "action_scale"
        )
        model._target_latent_mean = model._validate_vector(
            data.get("target_latent_mean", [0.0] * model.latent_dim),
            model.latent_dim,
            "target_latent_mean",
        )

        def _load_param_group(
            raw_group: Dict[str, Any],
            expected_shapes: Dict[str, Tuple[int, ...]],
        ) -> Dict[str, Any]:
            if not isinstance(raw_group, dict):
                raise ValueError("Missing weight group in serialized JEPA payload.")
            loaded: Dict[str, Any] = {}
            for key, shape in expected_shapes.items():
                if key not in raw_group:
                    raise ValueError(f"Missing weight tensor '{key}' in serialized JEPA payload.")
                val = raw_group[key]
                if len(shape) == 2:
                    if not isinstance(val, list) or len(val) != shape[0] or any(
                        not isinstance(r, list) or len(r) != shape[1] for r in val
                    ):
                        raise ValueError(f"Invalid shape for '{key}', expected {shape}.")
                    plain = _py_copy_2d(val)
                else:
                    if not isinstance(val, list) or len(val) != shape[0]:
                        raise ValueError(f"Invalid shape for '{key}', expected {shape}.")
                    plain = _py_copy_1d(val)
                loaded[key] = np.array(plain, dtype=np.float64) if model._use_numpy else plain
            return loaded

        enc_shapes = {
            "W1": (model.state_dim, model.hidden_dim),
            "b1": (model.hidden_dim,),
            "ln_g": (model.hidden_dim,),
            "ln_b": (model.hidden_dim,),
            "W2": (model.hidden_dim, model.latent_dim),
            "b2": (model.latent_dim,),
            "W_skip": (model.state_dim, model.latent_dim),
        }
        pred_shapes = {
            "Wp1": (model.latent_dim + model.action_dim, model.hidden_dim),
            "bp1": (model.hidden_dim,),
            "Wp2": (model.hidden_dim, model.latent_dim),
            "bp2": (model.latent_dim,),
        }

        if "online_encoder" in data:
            model._online_params = _load_param_group(data["online_encoder"], enc_shapes)
        if "target_encoder" in data:
            model._target_params = _load_param_group(data["target_encoder"], enc_shapes)
        if "predictor" in data:
            model._pred_params = _load_param_group(data["predictor"], pred_shapes)

        return model
