#!/usr/bin/env python3
"""
Mutual‑TLS reverse proxy in Python (aiohttp + ssl + cryptography)

• Terminates HTTPS with *client certificate required* (mTLS)
• Logs client certificate metadata (subject, issuer, serial, SAN, validity, thumbprint)
• Proxies the HTTP request to a configured upstream and injects X-Client-Cert header

Usage (example):
  pip install aiohttp cryptography
  python mtls_reverse_proxy.py \
      --listen-host 0.0.0.0 --listen-port 8443 \
      --server-cert ./server.crt --server-key ./server.key \
      --client-ca ./trusted_clients.pem \
      --upstream https://httpbin.org

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
  # Start proxy, then test:
  #   curl -vk https://localhost:8443/get \
  #        --cacert ca.crt \
  #        --cert client.crt --key client.key

NOTE: For production, use a real CA, strong ciphers, and proper hardening.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import logging
import ssl
from typing import Optional, Tuple, List

from aiohttp import web, ClientSession

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.x509.oid import NameOID, ExtensionOID
except Exception as e:  # pragma: no cover
    raise SystemExit("This script requires the 'cryptography' package. Install with: pip install cryptography") from e


HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}


def make_server_ssl_context(server_cert: str, server_key: str, client_ca: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Server's own cert/key
    ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
    # Trust store for verifying client certs
    ctx.load_verify_locations(cafile=client_ca)
    ctx.verify_mode = ssl.CERT_REQUIRED  # require client cert (mTLS)
    # Optional hardening
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # You can tune ciphers here if needed; Python's defaults are reasonable on modern OpenSSL
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
    not_before = cert.not_valid_before_utc.isoformat()
    not_after = cert.not_valid_after_utc.isoformat()
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


class MTLSProxy:
    def __init__(self, upstream: str, header_name: str, forward_subject_issuer: bool, xclient_format: str):
        self.upstream = upstream.rstrip('/')
        self.header_name = header_name
        self.forward_subject_issuer = forward_subject_issuer
        assert xclient_format in {"der-base64", "pem-oneline"}
        self.xclient_format = xclient_format
        self.client = ClientSession()

    async def close(self):
        await self.client.close()

    async def handler(self, request: web.Request) -> web.StreamResponse:
        sslobj: Optional[ssl.SSLObject] = request.transport.get_extra_info("ssl_object")
        if sslobj is None:
            return web.Response(status=400, text="TLS object missing on request. This endpoint requires HTTPS.")

        der: Optional[bytes] = None
        try:
            der = sslobj.getpeercert(binary_form=True)
        except Exception:
            der = None

        if not der:
            return web.Response(status=496, text="Client certificate required")  # 496 like nginx

        # Build header payload from client cert
        if self.xclient_format == "der-base64":
            xclient_value = der_to_base64(der)
        else:
            xclient_value = pem_to_oneline(der_to_pem(der))

        meta = parse_cert_metadata(der)
        logging.info(
            "mTLS client cert: subject=%s | issuer=%s | serial=%s | not_after=%s | thumb256=%s | SAN=%s",
            meta["subject"], meta["issuer"], meta["serial"], meta["not_after"], meta["thumbprint_sha256"], meta["san"],
        )

        # Prepare upstream request
        upstream_url = f"{self.upstream}{request.rel_url}"

        # Copy headers and strip hop-by-hop
        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
        # Overwrite Host to upstream host
        # aiohttp will set Host from the URL automatically if we don't set it; ensure removal
        fwd_headers.pop("Host", None)
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
            out = web.StreamResponse(status=resp.status, reason=resp.reason, headers=headers)
            await out.prepare(request)
            async for chunk in resp.content.iter_chunked(64 * 1024):
                await out.write(chunk)
            await out.write_eof()
            return out


async def init_app(args) -> Tuple[web.Application, ssl.SSLContext]:
    app = web.Application()
    proxy = MTLSProxy(
        upstream=args.upstream,
        header_name=args.header_name,
        forward_subject_issuer=args.forward_subject_issuer,
        xclient_format=args.xclient_format,
    )

    app.add_routes([web.route('*', '/{tail:.*}', proxy.handler)])

    async def on_cleanup(app: web.Application):
        await proxy.close()

    app.on_cleanup.append(on_cleanup)

    ssl_ctx = make_server_ssl_context(args.server_cert, args.server_key, args.client_ca)
    return app, ssl_ctx


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="mTLS reverse proxy with X-Client-Cert injection")
    p.add_argument("--listen-host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p.add_argument("--listen-port", type=int, default=8443, help="Bind port (default: 8443)")
    p.add_argument("--server-cert", required=True, help="Path to server certificate (PEM)")
    p.add_argument("--server-key", required=True, help="Path to server private key (PEM)")
    p.add_argument("--client-ca", required=True, help="Path to CA bundle used to verify client certs (PEM)")
    p.add_argument("--upstream", required=True, help="Upstream base URL, e.g. https://backend.local:443")
    p.add_argument("--header-name", default="X-Client-Cert", help="Header to carry client cert (default: X-Client-Cert)")
    p.add_argument("--xclient-format", choices=["der-base64", "pem-oneline"], default="der-base64",
                   help="Encoding for client cert header value (default: der-base64)")
    p.add_argument("--forward-subject-issuer", action="store_true", help="Also add X-SSL-Subject/X-SSL-Issuer headers")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]) 
    return p


def main():
    args = build_arg_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(message)s")

    app, ssl_ctx = asyncio.get_event_loop().run_until_complete(init_app(args))
    web.run_app(app, host=args.listen_host, port=args.listen_port, ssl_context=ssl_ctx, access_log=None)


if __name__ == "__main__":
    main()
