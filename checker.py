import base64
import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote

import requests


# ==================================================
# FLOGGER VPN CHECKER (Robust & Optimized v6.1)
# ==================================================

VERSION = "6.1"

TEST_URLS = {
    "google": "https://www.gstatic.com/generate_204",
}

IP_URL = "http://ip-api.com/json/?fields=status,message,country,countryCode,query"

TIMEOUT = 10      # Увеличенный таймаут для стабильности сбора
START_TIMEOUT = 5
RETRIES = 1
RETRY_DELAY = 1

SING_BOX = "sing-box"

COUNTRIES = {
    "DE": ("🇩🇪", "Германия"),
    "NL": ("🇳🇱", "Нидерланды"),
    "PL": ("🇵🇱", "Польша"),
    "FI": ("🇫🇮", "Финляндия"),
    "SE": ("🇸🇪", "Швеция"),
    "NO": ("🇳🇴", "Норвегия"),
    "FR": ("🇫🇷", "Франция"),
    "GB": ("🇬🇧", "Великобритания"),
    "US": ("🇺🇸", "США"),
    "CA": ("🇨🇦", "Канада"),
    "CH": ("🇨🇭", "Швейцария"),
    "AT": ("🇦🇹", "Австрия"),
    "BE": ("🇧🇪", "Бельгия"),
    "ES": ("🇪🇸", "Испания"),
    "IT": ("🇮🇹", "Италия"),
    "CZ": ("🇨🇿", "Чехия"),
    "RO": ("🇷🇴", "Румыния"),
    "BG": ("🇧🇬", "Болгария"),
    "TR": ("🇹🇷", "Турция"),
    "JP": ("🇯🇵", "Япония"),
    "SG": ("🇸🇬", "Сингапур"),
    "HK": ("🇭🇰", "Гонконг"),
    "RU": ("🇷🇺", "Россия"),
    "UA": ("🇺🇦", "Украина"),
    "BY": ("🇧🇾", "Беларусь"),
}


def decode_b64(value):
    value = value.strip()
    value += "=" * (-len(value) % 4)
    for altchars in (b"-_", b"+/"):
        try:
            decoded = base64.b64decode(value, altchars=altchars, validate=False)
            return decoded.decode("utf-8", errors="ignore")
        except Exception:
            continue
    return ""


def tls_config(params, default_server_name=""):
    security = params.get("security", [""])[0].lower()
    if security not in ("tls", "reality"):
        return {}

    sni = (
        params.get("sni", [""])[0]
        or params.get("serverName", [""])[0]
        or default_server_name
    )
    tls = {"enabled": True}
    if sni:
        tls["server_name"] = sni

    alpn = params.get("alpn", [""])[0]
    if alpn:
        tls["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]

    insecure = params.get("allowInsecure", params.get("insecure", ["false"]))[0].lower()
    if insecure in ("1", "true", "yes"):
        tls["insecure"] = True

    fingerprint = params.get("fp", [""])[0]
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

    if security == "reality":
        public_key = (
            params.get("pbk", [""])[0]
            or params.get("publicKey", [""])[0]
            or params.get("pk", [""])[0]
        )
        short_id = (
            params.get("sid", [""])[0]
            or params.get("shortId", [""])[0]
        )
        if public_key:
            tls["reality"] = {
                "enabled": True,
                "public_key": public_key,
                "short_id": short_id
            }

    return {"tls": tls}


def transport_config(params):
    kind = params.get("type", ["tcp"])[0].lower()
    if kind in ("tcp", ""):
        return {}

    if kind == "ws":
        path = params.get("path", ["/"])[0]
        host = params.get("host", [""])[0]
        result = {"type": "ws", "path": path, "headers": {}}
        if host:
            result["headers"]["Host"] = host
        return {"transport": result}

    if kind == "grpc":
        service = params.get("serviceName", [""])[0] or params.get("service_name", [""])[0]
        return {"transport": {"type": "grpc", "service_name": service}}

    if kind in ("xhttp", "splithttp"):
        return {"transport": {"type": "xhttp", "path": params.get("path", ["/"])[0], "host": params.get("host", [""])[0]}}

    if kind == "httpupgrade":
        return {"transport": {"type": "httpupgrade", "path": params.get("path", ["/"])[0], "host": params.get("host", [""])[0]}}

    if kind in ("http", "h2"):
        host = params.get("host", [""])[0]
        result = {"type": "http", "path": params.get("path", ["/"])[0]}
        if host:
            result["host"] = [host]
        return {"transport": result}

    if kind == "quic":
        return {"transport": {"type": "quic"}}

    return {}


def parse_vmess(link):
    raw = link[len("vmess://"):].strip()
    decoded_json = decode_b64(raw)
    if not decoded_json:
        raise ValueError("Invalid VMess base64")
    data = json.loads(decoded_json)
    host = data.get("add")
    port = int(data.get("port"))
    uuid = data.get("id")

    if not host or not port or not uuid:
        raise ValueError("Invalid VMess configuration")

    network = data.get("net", "tcp").lower()
    params = {
        "security": [data.get("tls", "")],
        "sni": [data.get("sni") or data.get("host", "")],
        "type": [network],
        "path": [data.get("path", "/")],
        "host": [data.get("host", "")],
        "fp": [data.get("fp", "")],
        "serviceName": [data.get("path", "")]
    }

    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "security": data.get("scy", "auto"),
        "alter_id": int(data.get("aid", 0))
    }
    outbound.update(tls_config(params, host))
    outbound.update(transport_config(params))
    return outbound


def parse_ss(link):
    parsed = urlsplit(link)
    if parsed.hostname and parsed.port:
        host = parsed.hostname
        port = parsed.port
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if not password:
            decoded = decode_b64(username)
            if ":" in decoded:
                method, password = decoded.split(":", 1)
            else:
                method, password = "aes-256-gcm", username
        else:
            method = username
    else:
        raw = link[len("ss://"):]
        decoded = decode_b64(raw.split("#", 1)[0])
        if "@" in decoded:
            credentials, address = decoded.rsplit("@", 1)
            method, password = credentials.split(":", 1)
            address_parsed = urlsplit("//" + address)
            host = address_parsed.hostname
            port = address_parsed.port
        else:
            raise ValueError("Unsupported Shadowsocks format")

    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password
    }


def parse_link(link):
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()

    if scheme == "vmess":
        return parse_vmess(link)
    if scheme == "ss":
        return parse_ss(link)

    parsed = urlsplit(link)
    params = parse_qs(parsed.query)
    host = parsed.hostname
    port = parsed.port

    if not host or not port:
        raise ValueError("Missing server address or port")

    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    if scheme == "vless":
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": username or "none"
        }
        flow = params.get("flow", [""])[0]
        if flow:
            outbound["flow"] = flow
        outbound.update(tls_config(params, host))
        outbound.update(transport_config(params))
        return outbound

    if scheme == "trojan":
        secret = password or username
        tls_params = dict(params)
        tls_params["security"] = ["tls"]
        outbound = {
            "type": "trojan",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "password": secret
        }
        outbound.update(tls_config(tls_params, host))
        outbound.update(transport_config(params))
        return outbound

    if scheme in ("hysteria2", "hy2"):
        secret = password or username
        tls = {"enabled": True, "server_name": params.get("sni", [host])[0]}
        insecure = params.get("insecure", ["0"])[0].lower()
        if insecure in ("1", "true", "yes"):
            tls["insecure"] = True
        return {
            "type": "hysteria2",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "password": secret,
            "tls": tls
        }

    raise ValueError(f"Unsupported protocol: {scheme}")


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(port, process):
    deadline = time.time() + START_TIMEOUT
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def check_ip(proxy):
    result = {"ip": None, "country": None, "country_code": None}
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.get(IP_URL, proxies={"http": proxy, "https": proxy}, timeout=TIMEOUT)
        data = response.json()
        if data.get("status") == "success":
            result["ip"] = data.get("query")
            result["country"] = data.get("country")
            result["country_code"] = data.get("countryCode")
    except Exception:
        pass
    finally:
        session.close()
    return result


def make_server_name(outbound, country_code=None):
    protocol = outbound["type"].upper()
    port = outbound["server_port"]
    if country_code:
        flag, country = COUNTRIES.get(country_code.upper(), ("🌍", country_code.upper()))
        return f"{flag} {country} | {protocol} | {port}"
    return f"🌐 Неизвестно | {protocol} | {port}"


def test_endpoint(session, url, proxies):
    for attempt in range(RETRIES):
        try:
            start_time = time.time()
            response = session.get(
                url,
                proxies=proxies,
                timeout=TIMEOUT,
                allow_redirects=False
            )
            ping_ms = int((time.time() - start_time) * 1000)
            if response.status_code == 204:
                return True, ping_ms
        except requests.RequestException:
            pass
        if attempt + 1 < RETRIES:
            time.sleep(RETRY_DELAY)
    return False, None


def check_link(link):
    results = {
        "working": False,
        "ping": None,
        "ip": None,
        "country": None,
        "country_code": None,
        "server_name": None,
        "protocol": None,
        "host": None,
        "port": None,
        "error": None
    }
    process = None
    session = requests.Session()
    session.trust_env = False

    try:
        outbound = parse_link(link)
        results["protocol"] = outbound["type"]
        results["host"] = outbound["server"]
        results["port"] = outbound["server_port"]

        port = get_free_port()
        config = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "local-in", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": "proxy"}
        }

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

            process = subprocess.Popen(
                [SING_BOX, "run", "-c", str(config_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            try:
                if not wait_for_port(port, process):
                    raise RuntimeError("sing-box did not start")

                proxy = f"http://127.0.0.1:{port}"
                proxies = {"http": proxy, "https": proxy}

                success, ping = test_endpoint(session, TEST_URLS["google"], proxies)
                results["working"] = success
                results["ping"] = ping

                if success:
                    results.update(check_ip(proxy))

                results["server_name"] = make_server_name(outbound, results["country_code"])
            finally:
                if process and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=2)
    except Exception as error:
        results["error"] = str(error)[:250]
    finally:
        if process and process.poll() is None:
            process.terminate()
        session.close()

    return results
