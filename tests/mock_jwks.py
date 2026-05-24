#!/usr/bin/env python3
"""
mock_jwks.py – Minimal OIDC / JWKS test server.

Endpoints
---------
GET  /.well-known/openid-configuration   OIDC discovery document
GET  /jwks                               JWK Set (RSA public key)
POST /token                              Issue a signed JWT

POST /token – supported grant types
  grant_type=password (default / shortcut for user tests)
    sub     – subject claim         (default: "test-user")
    roles   – comma-separated list  (default: "")
    scopes  – space-separated list  (default: "openid api:read")
    email   – email claim           (default: none)
    exp_in  – seconds until expiry  (default: 3600)

  grant_type=client_credentials  (machine-to-machine)
    client_id      – becomes the token sub  (default: "test-service")
    client_secret  – accepted as-is (not validated)
    scope          – space-separated scopes (default: "api:read")
    roles          – comma-separated roles  (default: "service")
    exp_in         – seconds until expiry   (default: 3600)

The RSA key-pair is generated once at startup and never persisted.
"""

import json
import time
import base64
import urllib.parse
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# ── Dependency bootstrap ──────────────────────────────────────────────────────
subprocess.check_call(
    [sys.executable, "-m", "pip", "install", "cryptography", "PyJWT", "--quiet"]
)

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt  # PyJWT

# ── Constants ─────────────────────────────────────────────────────────────────
ISSUER   = "http://mock-jwks:8888"
AUDIENCE = "test-client"
KID      = "integration-test-key-1"

# ── Key generation (once at startup) ─────────────────────────────────────────
_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
_public_key  = _private_key.public_key()
_private_pem = _private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
)

def _b64url(n: int) -> str:
    """Encode a big integer as base64url (no padding)."""
    byte_len = (n.bit_length() + 7) // 8
    raw = n.to_bytes(byte_len, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

_pub_numbers = _public_key.public_numbers()

JWK = {
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": KID,
    "n":   _b64url(_pub_numbers.n),
    "e":   _b64url(_pub_numbers.e),
}
JWKS = {"keys": [JWK]}

DISCOVERY = {
    "issuer":                 ISSUER,
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint":         f"{ISSUER}/token",
    "jwks_uri":               f"{ISSUER}/jwks",
    "introspection_endpoint": f"{ISSUER}/introspect",
    "response_types_supported":              ["code"],
    "subject_types_supported":               ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}

# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress per-request noise; errors still go to stderr

    # ── routing ───────────────────────────────────────────────────────────────

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            self._json(200, DISCOVERY)
        elif self.path == "/jwks":
            self._json(200, JWKS)
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path == "/token":
            self._issue_token()
        elif self.path == "/introspect":
            self._introspect()
        else:
            self._json(404, {"error": "not_found"})

    # ── /token ────────────────────────────────────────────────────────────────

    def _issue_token(self):
        params = self._read_form()

        def first(key, default=""):
            vals = params.get(key)
            return vals[0] if vals else default

        grant_type = first("grant_type", "password")

        if grant_type == "client_credentials":
            # ── Machine-to-machine ────────────────────────────────────────────
            client_id = first("client_id", "test-service")
            # client_secret is accepted but not validated (test server)
            scopes = first("scope", "api:read")
            roles  = [r for r in first("roles", "service").split(",") if r]
            sub    = client_id
            email  = None
        else:
            # ── User token (password shortcut for tests) ──────────────────────
            sub    = first("sub",    "test-user")
            roles  = [r for r in first("roles",  "").split(",") if r]
            scopes = first("scopes", "openid api:read")
            raw_email = first("email", "")
            email  = raw_email if raw_email else None

        exp_in = int(first("exp_in", "3600"))
        now    = int(time.time())

        payload = {
            "iss":   ISSUER,
            "aud":   AUDIENCE,
            "sub":   sub,
            "iat":   now,
            "nbf":   now,
            "exp":   now + exp_in,
            "scope": scopes,
            "roles": roles,
        }
        if email:
            payload["email"] = email

        token = jwt.encode(
            payload,
            _private_pem,
            algorithm="RS256",
            headers={"kid": KID},
        )
        self._json(200, {
            "access_token": token,
            "token_type":   "Bearer",
            "expires_in":   exp_in,
            "scope":        scopes,
        })

    # ── /introspect ───────────────────────────────────────────────────────────
    # Minimal RFC 7662 introspection — used when OAUTH2_STRATEGY=introspect.

    def _introspect(self):
        params = self._read_form()
        token  = (params.get("token") or [""])[0]

        try:
            data = jwt.decode(
                token,
                _public_key,
                algorithms=["RS256"],
                audience=AUDIENCE,
                options={"verify_iss": False},
            )
            self._json(200, {
                "active": True,
                "sub":    data.get("sub", ""),
                "scope":  data.get("scope", ""),
                "roles":  data.get("roles", []),
                "email":  data.get("email"),
                "exp":    data.get("exp"),
                "aud":    data.get("aud"),
            })
        except Exception:
            self._json(200, {"active": False})

    # ── helpers ───────────────────────────────────────────────────────────────

    def _read_form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode()
        return urllib.parse.parse_qs(body)

    def _json(self, status: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8888), Handler)
    print(f"mock-jwks listening on :8888  issuer={ISSUER}", flush=True)
    server.serve_forever()
