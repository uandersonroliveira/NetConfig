import json
import ssl
import os
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from .api.routes import router as api_router
from .api.websocket import manager

app = FastAPI(
    title="NetConfig",
    description="Network Switch Configuration Manager",
    version="1.0.0"
)

app.include_router(api_router)

static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def root():
    """Serve the main web interface."""
    index_file = static_dir / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "NetConfig API", "docs": "/docs"}


@app.websocket("/ws/progress")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time progress updates."""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


def load_config() -> dict:
    """Load application configuration."""
    config_file = Path(__file__).parent.parent / "config.json"
    if config_file.exists():
        with open(config_file, 'r') as f:
            return json.load(f)
    return {"server": {"host": "0.0.0.0", "port": 8443}}


def generate_self_signed_cert(cert_dir: Path) -> tuple[Path, Path]:
    """Generate self-signed SSL certificate if not exists."""
    cert_file = cert_dir / "server.crt"
    key_file = cert_dir / "server.key"

    if cert_file.exists() and key_file.exists():
        return cert_file, key_file

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        import datetime
        import socket

        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Get hostname for certificate
        hostname = socket.gethostname()

        # Build certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetConfig"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        # Add Subject Alternative Names
        san = x509.SubjectAlternativeName([
            x509.DNSName(hostname),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )

        # Write private key
        cert_dir.mkdir(parents=True, exist_ok=True)
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Write certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"Generated self-signed SSL certificate: {cert_file}")
        return cert_file, key_file

    except ImportError:
        print("WARNING: cryptography package not found. Cannot generate SSL certificate.")
        print("Install with: pip install cryptography")
        raise


def initialize_first_run():
    """Initialize first-run setup including admin user creation."""
    from .api.auth import create_initial_admin

    username, password = create_initial_admin()
    if username and password:
        print("\n" + "!" * 60)
        print("  FIRST RUN - INITIAL ADMIN CREDENTIALS")
        print("!" * 60)
        print(f"\n  Username: {username}")
        print(f"  Password: {password}")
        print("\n  IMPORTANT: Save these credentials securely!")
        print("  You will be required to change the password on first login.")
        print("\n" + "!" * 60 + "\n")


if __name__ == "__main__":
    import ipaddress

    config = load_config()
    server_config = config.get("server", {})

    # SSL certificate paths
    data_dir = Path(__file__).parent.parent / "data"
    cert_dir = data_dir / "ssl"

    # Generate or use existing certificates
    try:
        cert_file, key_file = generate_self_signed_cert(cert_dir)
    except Exception as e:
        print(f"ERROR: Failed to setup SSL certificates: {e}")
        print("HTTPS is required for security. Please install cryptography package.")
        exit(1)

    # Initialize first-run (create admin user if needed)
    initialize_first_run()

    host = server_config.get("host", "0.0.0.0")
    port = server_config.get("port", 8443)

    print("\n" + "=" * 60)
    print("  NetConfig - Network Switch Configuration Manager")
    print("=" * 60)
    print(f"\n  Web Interface: https://{host}:{port}")
    print(f"  API Documentation: https://{host}:{port}/docs")
    print("\n  NOTE: Using self-signed certificate.")
    print("  Your browser may show a security warning - this is expected.")
    print("=" * 60 + "\n")

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        ssl_keyfile=str(key_file),
        ssl_certfile=str(cert_file)
    )
