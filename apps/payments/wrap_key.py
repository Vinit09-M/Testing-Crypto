"""Testing-Crypto adapter for 256-bit data keys.

Deploy the reader with both keys before switching the writer to the hybrid
public key. Provision the CipherSetu CLI and keys outside source control.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# The prefix distinguishes the hybrid envelope from an unframed wrapped key.
HYBRID_PREFIX = b"Testing-Crypto/CipherSetu/v1\x00"


HYBRID_SUITE = "HPKE-MLKEM768-X25519-HKDFSHA256-AES256GCM"


def _run_cli(cli: Path, operation: str, data: bytes, key: Path) -> bytes:
    executable = cli.resolve(strict=True)
    key = key.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="testing-crypto-") as directory:
        source = Path(directory) / "input"
        output = Path(directory) / "output"
        with open(source, "xb", opener=_private_file) as stream:
            stream.write(data)
        flag = "--public" if operation == "encrypt" else "--private"
        subprocess.run(
            [str(executable), operation, "--in", str(source), flag, str(key),
             "--out", str(output)],
            check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return output.read_bytes()


def _private_file(path, flags):
    import os

    return os.open(path, flags, 0o600)


def _data_key(data: bytes) -> bytes:
    if len(data) != 32:
        raise ValueError("expected a 256-bit data key")
    return data


def wrap_data_key(hybrid_public_key: Path, data_key: bytes, *, cli: Path) -> bytes:
    """Return a framed CipherSetu hybrid envelope containing the data key."""
    envelope = _run_cli(cli, "encrypt", _data_key(data_key), hybrid_public_key)
    if json.loads(envelope)["suite"] != HYBRID_SUITE:
        raise ValueError("expected the CipherSetu hybrid suite")
    return HYBRID_PREFIX + envelope


def unwrap_data_key(
    wrapped: bytes, *, cli: Path, hybrid_private_key: Path | None = None,
    legacy_private_key: rsa.RSAPrivateKey | None = None,
) -> bytes:
    """Open a hybrid envelope or the fixture's original unframed OAEP value."""
    if wrapped.startswith(HYBRID_PREFIX):
        if hybrid_private_key is None:
            raise ValueError("hybrid private key required")
        # Authentication errors from this path propagate without a fallback.
        return _data_key(_run_cli(cli, "decrypt", wrapped[len(HYBRID_PREFIX):], hybrid_private_key))
    if legacy_private_key is None:
        raise ValueError("legacy private key required")
    algorithm = hashes.SHA256()
    oaep = padding.OAEP(mgf=padding.MGF1(algorithm), algorithm=algorithm, label=None)
    return _data_key(legacy_private_key.decrypt(wrapped, oaep))
