import base64
import json
import subprocess
import tempfile
import time
import socket
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote

import requests

TEST_URLS = {
    "cloudflare": "https://cp.cloudflare.com/generate_204",
    "google": "https://www.gstatic.com/generate_204",
}

TIMEOUT = 12


def decode_b64(value):
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value).decode("utf-8")


def tls_config(params):
    result = {}
    security = params.get("security", [""])[0].lower()
    sni = params.get("sni", [""])[0]

    if security in ("tls", "reality"):
        tls = {"enabled": True}

        if sni:
            tls["server_name"] = sni

        alpn = params.get("alpn", [""])[0]
        if alpn:
            tls["alpn"] = alpn.split(",")

        fp = params.get("fp", [""])[0]
        if fp:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fp
            }

        if security == "reality":
            public_key = params.get("pbk", [""])[0]
            short_id = params.get("sid", [""])[0]

            if not public_key:
                raise ValueError("Reality: missing public key")

            tls["reality"] = {
                "enabled": True,
                "public_key": public_key,
                "short_id": short_id
            }

        result["tls"] = tls

    return result


def transport_config(params):
    kind = params.get("type", ["tcp"])[0].lower()

    if kind == "tcp":
        return {}

    if kind == "ws":
        ws_path = params.get("path", ["/"])[0]
        host = params.get("host", [""])[0]

        headers = {}
        if host:
            headers["Host"] = host

        return {
            "transport": {
                "type": "ws",
                "path": ws_path,
                "headers": headers
            }
        }

    if kind == "grpc":
        service = params.get("serviceName", [""])[0]
        return {
            "transport": {
                "type": "grpc",
                "service_name": service
            }
        }

    if kind == "httpupgrade":
        return {
            "transport": {
                "type": "httpupgrade",
                "path": params.get("path", ["/"])[0],
                "host": params.get("host", [""])[0]
            }
        }

    raise ValueError(f"Unsupported transport: {kind}")


def parse_vmess(link):
    raw = link[len("vmess://"):]
    data = json.loads(decode_b64(raw))

    params = {
        "security": [data.get("tls", "")],
        "sni": [data.get("sni") or data.get("host", "")],
        "type": [data.get("net", "tcp")],
        "path": [data.get("path", "/")],
        "host": [data.get("host", "")],
        "fp": [data.get("fp", "")]
    }

    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": data["add"],
        "server_port": int(data["port"]),
        "uuid": data["id"],
        "security": data.get("scy", "auto"),
        "alter_id": int(data.get("aid", 0)),
    }

    outbound.update(tls_config(params))
    outbound.update(transport_config(params))
    return outbound


def parse_link(link):
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()

    if scheme == "vmess":
        return parse_vmess(link)

    parsed = urlsplit(link)
    params = parse_qs(parsed.query)
    host = parsed.hostname
    port = parsed.port

    if not host or not port:
        raise ValueError("Missing server address or port")

    if scheme == "vless":
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": unquote(parsed.username or "")
        }

        flow = params.get("flow", [""])[0]
        if flow:
            outbound["flow"] = flow

        outbound.update(tls_config(params))
        outbound.update(transport_config(params))
        return outbound

    if scheme == "trojan":
        outbound = {
            "type": "trojan",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "password": unquote(parsed.username or "")
        }

        outbound.update(tls_config(params))
        outbound.update(transport_config(params))
        return outbound

    if scheme in ("hysteria2", "hy2"):
        outbound = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "password": unquote(parsed.username or ""),
            "tls": {
                "enabled": True,
                "server_name": params.get("sni", [host])[0]
            }
        }

        obfs = params.get("obfs", [""])[0]
        obfs_password = params.get("obfs-password", [""])[0]

        if obfs:
            outbound["obfs"] = {
                "type": obfs,
                "password": obfs_password
            }

        return outbound

    if scheme == "ss":
        raw_user = parsed.username or ""
        raw_password = parsed.password or ""

        if not raw_password and raw_user:
            decoded = decode_b64(raw_user)
            if ":" not in decoded:
                raise ValueError("Invalid Shadowsocks credentials")
            method, password = decoded.split(":", 1)
        else:
            method = unquote(raw_user)
            password = unquote(raw_password)

        return {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "method": method,
            "password": password
        }

    raise ValueError(f"Unsupported protocol: {scheme}")


def wait_for_port(port, process):
    deadline = time.time() + 8

    while time.time() < deadline:
        if process.poll() is not None:
            return False

        try:
            with socket.create_connection(
                ("127.0.0.1", port), timeout=0.5
            ):
                return True
        except OSError:
            time.sleep(0.25)

    return False


def check_link(link, port=20808):
    results = {
        "cloudflare": False,
        "google": False,
        "working": False,
        "error": None
    }

    process = None

    try:
        outbound = parse_link(link)

        config = {
            "log": {"level": "error"},
            "inbounds": [{
                "type": "mixed",
                "tag": "local-in",
                "listen": "127.0.0.1",
                "listen_port": port
            }],
            "outbounds": [
                outbound,
                {"type": "direct", "tag": "direct"}
            ],
            "route": {"final": "proxy"}
        }

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(
                json.dumps(config),
                encoding="utf-8"
            )

            subprocess.run(
                ["sing-box", "check", "-c", str(config_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=10
            )

            process = subprocess.Popen(
                ["sing-box", "run", "-c", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            if not wait_for_port(port, process):
                raise RuntimeError("sing-box did not start")

            proxy = f"http://127.0.0.1:{port}"
            proxies = {
                "http": proxy,
                "https": proxy
            }

            # Always test both services, even if the first fails.
            for name, url in TEST_URLS.items():
                try:
                    response = requests.get(
                        url,
                        proxies=proxies,
                        timeout=TIMEOUT
                    )
                    results[name] = response.status_code == 204
                except requests.RequestException:
                    results[name] = False

            results["working"] = (
                results["cloudflare"] or results["google"]
            )

    except Exception as error:
        results["error"] = str(error)[:250]

    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()

    return results
      
