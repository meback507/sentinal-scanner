"""
ThreatGate Cryptographic Engine
RFC 8032 compliant Ed25519 asymmetric digital signatures binding source code digest to threat model reports.
"""

import base64
import hashlib
import re
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

SEAL_HEADER = "<!-- SECURITY TAMPER-PROOF SEAL (Ed25519) -->"
SEAL_REGEX = r"\*\*Digital Seal:\*\*\s*`([^`]+)`"


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generates an Ed25519 private and public keypair in standard PEM format.
    Returns: (private_key_pem: bytes, public_key_pem: bytes)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def compute_code_digest(code_content: str) -> str:
    """Computes a canonical SHA-256 digest of the source code content."""
    normalized = code_content.replace("\r\n", "\n").strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def sign_payload(code_content: str, report_body: str, private_key_pem: bytes) -> str:
    """
    Signs the combination of SHA-256(code) and the report body using the Ed25519 private key.
    Returns a Base64-encoded signature.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    code_hash = compute_code_digest(code_content)
    normalized_report = report_body.replace("\r\n", "\n").strip()

    payload = f"{code_hash}\n{normalized_report}".encode("utf-8")
    signature = private_key.sign(payload)
    return base64.b64encode(signature).decode("utf-8")


def verify_payload(code_content: str, report_body: str, signature_b64: str, public_key_pem: bytes) -> bool:
    """
    Verifies that the report was signed by the authorized private key and that neither
    the source code nor the report body has drifted or been tampered with.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        code_hash = compute_code_digest(code_content)
        normalized_report = report_body.replace("\r\n", "\n").strip()
        payload = f"{code_hash}\n{normalized_report}".encode("utf-8")

        signature = base64.b64decode(signature_b64.strip())
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False


def extract_seal_from_markdown(markdown_content: str) -> Tuple[str, Optional[str]]:
    """
    Splits a *.threat.md file into:
    (report_body: str, digital_seal_b64: Optional[str])
    """
    content = markdown_content.replace("\r\n", "\n")
    if SEAL_HEADER in content:
        parts = content.split(SEAL_HEADER)
        body = parts[0].strip()
        seal_section = parts[1]
        match = re.search(SEAL_REGEX, seal_section)
        seal = match.group(1).strip() if match else None
        return body, seal

    # Fallback search if header altered
    match = re.search(SEAL_REGEX, content)
    if match:
        seal = match.group(1).strip()
        body = content[:match.start()].strip()
        return body, seal

    return content.strip(), None


def embed_seal_into_markdown(report_body: str, seal_b64: str) -> str:
    """Appends the standard cryptographic tamper-proof seal block to a report."""
    body = report_body.replace("\r\n", "\n").strip()
    return (
        f"{body}\n\n"
        f"{SEAL_HEADER}\n"
        f"**Digital Seal:** `{seal_b64}`\n"
    )

