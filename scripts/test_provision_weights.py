"""Unit tests for provision-weights.py's envelope encryption.

Run with:  uv run --with 'PyJWT[crypto]' --with pytest --with requests pytest scripts/

The decrypting peer is launcher/src/artifacts.rs; the shared test vectors
live in launcher/tests/fixtures/artifact-envelope.json (regenerate with
provision-weights.py --write-fixture and re-run cargo test on any change).
"""

import importlib.util
import io
import pathlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

spec = importlib.util.spec_from_file_location(
    "provision_weights", pathlib.Path(__file__).parent / "provision-weights.py"
)
pw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pw)

FIXTURE = (
    pathlib.Path(__file__).parent.parent
    / "launcher" / "tests" / "fixtures" / "artifact-envelope.json"
)

DEK = bytes(range(32))
NONCE_PREFIX = b"\xaa" * 7


def decrypt_stream(ciphertext: bytes, dek: bytes, nonce_prefix: bytes,
                   chunk_size: int) -> bytes:
    """Test-only mirror of the launcher's EnvelopeDecryptor."""
    aead = ChaCha20Poly1305(dek)
    segment = chunk_size + pw.TAG_SIZE
    segments = [ciphertext[i:i + segment] for i in range(0, len(ciphertext), segment)]
    out = b""
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        nonce = nonce_prefix + i.to_bytes(4, "big") + (b"\x01" if last else b"\x00")
        out += aead.decrypt(nonce, seg, pw.ENVELOPE_AAD)
    return out


def seal(plaintext: bytes, chunk_size: int) -> tuple[bytes, int, str]:
    out = io.BytesIO()
    size, sha = pw.encrypt_stream(io.BytesIO(plaintext), out, DEK, NONCE_PREFIX, chunk_size)
    return out.getvalue(), size, sha


@pytest.mark.parametrize(
    "length", [0, 1, 10, 32, 33, 64, 100], ids=lambda n: f"len={n}"
)
def test_roundtrip(length):
    plaintext = bytes(i % 251 for i in range(length))
    ciphertext, size, sha = seal(plaintext, chunk_size=32)
    assert size == length
    assert decrypt_stream(ciphertext, DEK, NONCE_PREFIX, 32) == plaintext
    n_segments = max(1, -(-length // 32))  # empty plaintext = one empty segment
    assert len(ciphertext) == length + n_segments * pw.TAG_SIZE


def test_sha256_is_of_the_plaintext():
    import hashlib
    plaintext = b"weights bytes"
    _, _, sha = seal(plaintext, chunk_size=32)
    assert sha == hashlib.sha256(plaintext).hexdigest()


def test_tampered_ciphertext_fails():
    ciphertext, _, _ = seal(b"a" * 100, chunk_size=32)
    tampered = bytearray(ciphertext)
    tampered[40] ^= 1
    with pytest.raises(InvalidTag):
        decrypt_stream(bytes(tampered), DEK, NONCE_PREFIX, 32)


def test_truncated_ciphertext_fails():
    """Dropping the final segment must not pass: its nonce carried the
    last-flag, so the new last segment authenticates with the wrong flag."""
    ciphertext, _, _ = seal(b"a" * 100, chunk_size=32)
    truncated = ciphertext[: 2 * (32 + pw.TAG_SIZE)]
    with pytest.raises(InvalidTag):
        decrypt_stream(truncated, DEK, NONCE_PREFIX, 32)


def test_reordered_segments_fail():
    ciphertext, _, _ = seal(b"a" * 100, chunk_size=32)
    segment = 32 + pw.TAG_SIZE
    swapped = (
        ciphertext[segment: 2 * segment]
        + ciphertext[:segment]
        + ciphertext[2 * segment:]
    )
    with pytest.raises(InvalidTag):
        decrypt_stream(swapped, DEK, NONCE_PREFIX, 32)


def test_rejects_bad_key_material():
    with pytest.raises(ValueError):
        pw.encrypt_stream(io.BytesIO(b""), io.BytesIO(), b"short", NONCE_PREFIX)
    with pytest.raises(ValueError):
        pw.encrypt_stream(io.BytesIO(b""), io.BytesIO(), DEK, b"\xaa" * 12)


def test_fixture_file_is_up_to_date():
    """The checked-in Rust interop fixture must match what this code emits.
    Regenerate with: scripts/provision-weights.py --write-fixture <path>"""
    assert FIXTURE.read_text() == pw.fixture_json()


# ---- download resilience (offline; no real HF) ------------------------------

def _flaky_server(payload: bytes, drop_at: int):
    """An HTTP server that honors Range but slams the connection shut partway
    through the *first* response — exactly the mid-stream drop HF gave us."""
    served = []  # the start offset of every GET, in order

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            rng = self.headers.get("Range")
            start = int(rng.split("=", 1)[1].split("-", 1)[0]) if rng else 0
            served.append(start)
            body = payload[start:]
            if rng:
                self.send_response(206)
                self.send_header(
                    "Content-Range",
                    f"bytes {start}-{len(payload) - 1}/{len(payload)}")
            else:
                self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            if len(served) == 1:
                # first hit: write a prefix, then drop the connection so the
                # client sees an incomplete read (declared length unfulfilled)
                self.wfile.write(body[:drop_at])
                self.wfile.flush()
                self.connection.close()
            else:
                self.wfile.write(body)

    httpd = HTTPServer(("localhost", 0), Handler)
    return httpd, served


def test_download_resumes_after_midstream_drop(tmp_path, monkeypatch):
    monkeypatch.setattr(pw.time, "sleep", lambda *_: None)  # no backoff wait
    payload = bytes(i % 251 for i in range(50_000))
    httpd, served = _flaky_server(payload, drop_at=20_000)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]
        out = pw.download_model(
            f"http://localhost:{port}/model.gguf", tmp_path,
            chunk_size=4096,  # small so a sub-chunk drop still shows resume
            stall_window_s=0.0, stall_min_bytes=0)  # stall guard disabled
    finally:
        httpd.shutdown()
        thread.join()
    assert out.read_bytes() == payload
    # exactly two GETs: the second carried a Range starting past byte 0 —
    # iter_content drops the in-flight chunk, so resume lands on a chunk
    # boundary at-or-before the drop, never a full restart from 0
    assert len(served) == 2
    assert served[0] == 0
    assert 0 < served[1] <= 20_000
    assert not (tmp_path / "model.gguf.part").exists()


def test_download_short_circuits_when_already_present(tmp_path):
    target = tmp_path / "model.gguf"
    target.write_bytes(b"already here")
    # no server: a re-download attempt would fail, proving the cache hit
    out = pw.download_model("http://127.0.0.1:1/model.gguf", tmp_path)
    assert out == target


def test_stall_guard_aborts_on_trickle():
    now = [0.0]
    guard = pw._StallGuard(window_s=10.0, min_bytes=1000, clock=lambda: now[0])
    guard.update(500)            # within the window: no decision yet
    now[0] = 11.0
    with pytest.raises(pw._StallError):
        guard.update(900)        # 900 B over 11 s is below the 1000 B floor


def test_stall_guard_allows_steady_progress():
    now = [0.0]
    guard = pw._StallGuard(window_s=10.0, min_bytes=1000, clock=lambda: now[0])
    now[0] = 11.0
    guard.update(5000)           # plenty of progress: window resets
    now[0] = 22.0
    guard.update(11000)          # still healthy: no raise
