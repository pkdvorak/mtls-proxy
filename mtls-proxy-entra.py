#!/usr/bin/env python3
"""
Mutual‑TLS + Entra ID (Azure AD) JWT‑guarded reverse proxy in Python (aiohttp + ssl + cryptography + PyJWT)

• Terminates HTTPS with *client certificate required* (mTLS)
• Validates an incoming OAuth 2.0 / OpenID Connect access token (JWT) issued by Microsoft Entra ID
  - Expects `Authorization: Bearer <token>` (configurable alternate header)
  - Verifies signature using Entra JWKS, `aud`, `iss`, `exp`, `nbf`
  - Optional allow‑list for scopes (scp) and/or app roles (roles)
• Logs client certificate metadata (subject, issuer, serial, SAN, validity, thumbprint)
• If token is invalid → log and drop (HTTP 401), do **not** forward
• If valid → proxies the HTTP request to a configured upstream and injects X-Client-Cert header

Usage (example):
  pip install aiohttp cryptography PyJWT
  python mtls_reverse_proxy.py \
      --listen-host 0.0.0.0 --listen-port 8443 \
      --server-cert ./server.crt --server-key ./server.key \
      --client-ca ./trusted_clients.pem \
      --upstream https://httpbin.org \
      --aad-tenant <TENANT_ID or domain> \
      --aad-audience api://your-app-id-or-uri \
      --require-scopes "read write" \
      --forward-subject-issuer

Testing mTLS quickly (self‑signed demo):
  # 1) Create test CA and client certs (for demo only!)
  # openssl genrsa -out ca.key 2048
  # openssl req -x509 -new -key ca.key -subj "/CN=Test CA" -days 365 -out ca.crt
  # openssl genrsa -out server.key 2048
  # openssl req -new -key server.key -subj "/CN=localhost" -out server.csr
  # openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out server.crt
  # openssl genrsa -out client.key 2048
  # openssl req -new -key client.key -subj "/CN=alice@example.com" -out client.csr
  # openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out client.crt
  # Client PEM (for curl):
  #   cat client.key client.crt > client.pem
  # Start proxy, then test mTLS + token (replace <TOKEN>):
  #   curl -vk https://localhost:8443/get \
  #        --cacert ca.crt \
  #        --cert client.crt --key client.key \
  #        -H "Authorization: Bearer <TOKEN>"

NOTE: For production, use a real CA, strong ciphers, and proper hardening.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import logging
import ssl
from typing import Optional, Tuple, List, Sequence

import aiohttp
from aiohttp import web, ClientSession

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import ExtensionOID
except Exception as e:  # pragma: no cover
    raise SystemExit("This script requires the 'cryptography' package. Install with: pip install cryptography") from e

try:
    import jwt
    from jwt import PyJWKClient
except Exception as e:  # pragma: no cover
    raise SystemExit("This script requires 'PyJWT'. Install with: pip install PyJWT") from e


HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}


# ----------------------------- TLS helpers -----------------------------

def make_server_ssl_context(server_cert: str, server_key: str, client_ca: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Server's own cert/key
    ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
    # Trust store for verifying client certs
    ctx.load_verify_locations(cafile=client_ca)
    ctx.verify_mode = ssl.CERT_REQUIRED  # require client cert (mTLS)
    # Optional hardening
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def der_to_pem(der: bytes) -> str:
    pem = ssl.DER_cert_to_PEM_cert(der)
    return pem


def pem_to_oneline(pem: str) -> str:
    # Remove BEGIN/END lines and newlines for header safety (URL-safe base64 is also fine)
    body_lines = [line for line in pem.splitlines() if not line.startswith("-----")]
    return "".join(body_lines)


def der_to_base64(der: bytes) -> str:
    return base64.b64encode(der).decode("ascii")


def parse_cert_metadata(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)

    def _name_to_str(name: x509.Name) -> str:
        return ", ".join([f"{attr.oid._name}={attr.value}" for attr in name])

    subject = _name_to_str(cert.subject)
    issuer = _name_to_str(cert.issuer)
    # cryptography >=41 has *_utc
    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before).isoformat()
    not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after).isoformat()
    serial = hex(cert.serial_number)
    thumb_sha256 = hashlib.sha256(der).hexdigest()

    san_list: List[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for entry in san:
            san_list.append(str(entry.value))
    except x509.ExtensionNotFound:
        pass

    eku_list: List[str] = []
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        for oid in eku:
            eku_list.append(oid.dotted_string)
    except x509.ExtensionNotFound:
        pass

    return {
        "subject": subject,
        "issuer": issuer,
        "serial": serial,
        "not_before": not_before,
        "not_after": not_after,
        "san": san_list,
        "eku": eku_list,
        "thumbprint_sha256": thumb_sha256,
    }


# ----------------------------- Entra token validation -----------------------------

class EntraTokenValidator:
    def __init__(self, tenant: str, audience: str, issuer: Optional[str] = None,
                 authority_host: str = "https://login.microsoftonline.com",
                 allowed_scopes: Optional[Sequence[str]] = None,
                 allowed_roles: Optional[Sequence[str]] = None,
                 auth_header: str = "Authorization"):
        self.tenant = tenant
        self.audience = audience
        self.issuer = issuer or f"{authority_host.rstrip('/')}/{tenant}/v2.0"
        self.jwks_uri = f"{self.issuer}/discovery/v2.0/keys"
        self.allowed_scopes = set(allowed_scopes or [])
        self.allowed_roles = set(allowed_roles or [])
        self.auth_header = auth_header
        self._jwk_client = PyJWKClient(self.jwks_uri)

    def _extract_token(self, request: web.Request) -> Optional[str]:
        # Prefer configured header (default: Authorization)
        raw = request.headers.get(self.auth_header)
        if not raw:
            return None
        if self.auth_header.lower() == "authorization":
            if not raw.lower().startswith("bearer "):
                return None
            return raw.split(" ", 1)[1].strip()
        return raw.strip()

    def validate(self, request: web.Request) -> Tuple[bool, Optional[dict], Optional[str]]:
        """Return (is_valid, claims, error_text)."""
        token = self._extract_token(request)
        if not token:
            return False, None, "missing_token"
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except Exception as e:
            return False, None, f"jwt_invalid: {e}"

        # Optional scope/role filters
        if self.allowed_scopes:
            token_scopes = set((claims.get("scp") or "").split())
            if not token_scopes & self.allowed_scopes:
                return False, claims, "insufficient_scopes"
        if self.allowed_roles:
            token_roles = set(claims.get("roles") or [])
            if not token_roles & self.allowed_roles:
                return False, claims, "insufficient_roles"

        return True, claims, None


# ----------------------------- Proxy -----------------------------

class MTLSProxy:
    def __init__(self, upstream: str, header_name: str, forward_subject_issuer: bool, xclient_format: str,
                 validator: EntraTokenValidator):
        self.upstream = upstream.rstrip('/')
        self.header_name = header_name
        self.forward_subject_issuer = forward_subject_issuer
        assert xclient_format in {"der-base64", "pem-oneline"}
        self.xclient_format = xclient_format
        self.client = ClientSession()
        self.validator = validator

    async def close(self):
        await self.client.close()

    async def handler(self, request: web.Request) -> web.StreamResponse:
        # --- mTLS: ensure we have the client certificate ---
        sslobj: Optional[ssl.SSLObject] = request.transport.get_extra_info("ssl_object")
        if sslobj is None:
            return web.Response(status=400, text="TLS object missing on request. This endpoint requires HTTPS.")

        der: Optional[bytes] = None
        try:
            der = sslobj.getpeercert(binary_form=True)
        except Exception:
            der = None

        if not der:
            # 496 like nginx: client cert required
            logging.warning("drop_no_client_cert path=%s ip=%s", request.rel_url, request.remote)
            return web.Response(status=496, text="Client certificate required")

        meta = parse_cert_metadata(der)

        # --- Entra token validation ---
        ok, claims, err = self.validator.validate(request)
        if not ok:
            logging.warning(
                "drop_invalid_token reason=%s ip=%s subject=%s path=%s",
                err, request.remote, meta.get("subject"), request.rel_url,
            )
            # Drop by returning 401 without forwarding
            return web.Response(status=401, text="Unauthorized")

        # Log certificate (and selected token info) and continue
        logging.info(
            "mTLS OK; token OK: subject=%s issuer=%s thumb256=%s aud=%s azp=%s scp=%s roles=%s",
            meta["subject"], meta["issuer"], meta["thumbprint_sha256"],
            claims.get("aud"), claims.get("azp"), claims.get("scp"), claims.get("roles"),
        )

        # Build header payload from client cert
        if self.xclient_format == "der-base64":
            xclient_value = der_to_base64(der)
        else:
            xclient_value = pem_to_oneline(der_to_pem(der))

        # Prepare upstream request
        upstream_url = f"{self.upstream}{request.rel_url}"

        # Copy headers and strip hop-by-hop
        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
        fwd_headers.pop("Host", None)  # let aiohttp set Host from URL
        # Inject client cert header(s)
        fwd_headers[self.header_name] = xclient_value
        if self.forward_subject_issuer:
            fwd_headers.setdefault("X-SSL-Subject", meta["subject"])
            fwd_headers.setdefault("X-SSL-Issuer", meta["issuer"])

        # Stream request body to upstream
        async def _body_iter():
            async for chunk in request.content.iter_chunked(64 * 1024):
                yield chunk

        timeout = aiohttp.ClientTimeout(total=None)
        async with self.client.request(
            request.method,
            upstream_url,
            headers=fwd_headers,
            data=_body_iter(),
            allow_redirects=False,
            timeout=timeout,
        ) as resp:
            # Prepare streaming response back to client
            headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS]
            out = web.StreamResponse(status=resp.status, reason=resp.reason, headers=dict(headers))
            await out.prepare(request)
            async for chunk in resp.content.iter_chunked(64 * 1024):
                await out.write(chunk)
            await out.write_eof()
            return out


# ----------------------------- App bootstrap -----------------------------

async def init_app(args) -> Tuple[web.Application, ssl.SSLContext]:
    app = web.Application()

    validator = EntraTokenValidator(
        tenant=args.aad_tenant,
        audience=args.aad_audience,
        issuer=args.aad_issuer,
        authority_host=args.aad_authority,
        allowed_scopes=args.require_scopes.split() if args.require_scopes else None,
        allowed_roles=args.require_roles.split() if args.require_roles else None,
        auth_header=args.auth_header,
    )

    proxy = MTLSProxy(
        upstream=args.upstream,
        header_name=args.header_name,
        forward_subject_issuer=args.forward_subject_issuer,
        xclient_format=args.xclient_format,
        validator=validator,
    )

    app.add_routes([web.route('*', '/{tail:.*}', proxy.handler)])

    async def on_cleanup(app: web.Application):
        await proxy.close()

    app.on_cleanup.append(on_cleanup)

    ssl_ctx = make_server_ssl_context(args.server_cert, args.server_key, args.client_ca)
    return app, ssl_ctx


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="mTLS + Entra‑guarded reverse proxy with X-Client-Cert injection")
    # Listener / TLS
    p.add_argument("--listen-host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p.add_argument("--listen-port", type=int, default=8443, help="Bind port (default: 8443)")
    p.add_argument("--server-cert", required=True, help="Path to server certificate (PEM)")
    p.add_argument("--server-key", required=True, help="Path to server private key (PEM)")
    p.add_argument("--client-ca", required=True, help="Path to CA bundle used to verify client certs (PEM)")
    # Upstream
    p.add_argument("--upstream", required=True, help="Upstream base URL, e.g. https://backend.local:443")
    p.add_argument("--header-name", default="X-Client-Cert", help="Header to carry client cert (default: X-Client-Cert)")
    p.add_argument("--xclient-format", choices=["der-base64", "pem-oneline"], default="der-base64",
                   help="Encoding for client cert header value (default: der-base64)")
    p.add_argument("--forward-subject-issuer", action="store_true", help="Also add X-SSL-Subject/X-SSL-Issuer headers")
    # Entra ID / OAuth settings
    p.add_argument("--aad-tenant", required=True, help="Tenant ID or verified domain (e.g. contoso.onmicrosoft.com)")
    p.add_argument("--aad-audience", required=True, help="Expected audience (Application ID URI or client ID)")
    p.add_argument("--aad-issuer", help="Override expected issuer (default: https://login.microsoftonline.com/<tenant>/v2.0)")
    p.add_argument("--aad-authority", default="https://login.microsoftonline.com", help="Authority host")
    p.add_argument("--require-scopes", help="Space-separated list of acceptable scopes (scp claim)")
    p.add_argument("--require-roles", help="Space-separated list of acceptable app roles (roles claim)")
    p.add_argument("--auth-header", default="Authorization", help="Header carrying token (default: Authorization)")
    # Logging
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]) 
    return p


def main():
    args = build_arg_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(message)s")

    app, ssl_ctx = asyncio.get_event_loop().run_until_complete(init_app(args))
    web.run_app(app, host=args.listen_host, port=args.listen_port, ssl_context=ssl_ctx, access_log=None)


if __name__ == "__main__":
    main()
