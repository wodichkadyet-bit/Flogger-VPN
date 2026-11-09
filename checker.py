import base64
import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import (
    urlsplit, urlunsplit, parse_qs,
    unquote, quote
)

import requests


# ==================================================
# FLOGGER VPN CHECKER
# ==================================================

VERSION = "2.0"

TEST_URLS = {
    "cloudflare": "https://cp.cloudflare.com/generate_204",
    "google": "https://www.gstatic.com/generate_204",
}

IP_URL = "https://ipwho.is/"

TIMEOUT = 12
START_TIMEOUT = 10
RETRIES = 2
RETRY_DELAY = 2

SING_BOX = "sing-box"

COUNTRIES = {
    "DE": ("🇩🇪", "Germany"),
    "NL": ("🇳🇱", "Netherlands"),
    "PL": ("🇵🇱", "Poland"),
    "FI": ("🇫🇮", "Finland"),
    "SE": ("🇸🇪", "Sweden"),
    "NO": ("🇳🇴", "Norway"),
    "FR": ("🇫🇷", "France"),
    "GB": ("🇬🇧", "United Kingdom"),
    "US": ("🇺🇸", "USA"),
    "CA": ("🇨🇦", "Canada"),
    "CH": ("🇨🇭", "Switzerland"),
    "AT": ("🇦🇹", "Austria"),
    "BE": ("🇧🇪", "Belgium"),
    "ES": ("🇪🇸", "Spain"),
    "IT": ("🇮🇹", "Italy"),
    "CZ": ("🇨🇿", "Czechia"),
    "RO": ("🇷🇴", "Romania"),
    "BG": ("🇧🇬", "Bulgaria"),
    "TR": ("🇹🇷", "Turkey"),
    "JP": ("🇯🇵", "Japan"),
    "SG": ("🇸🇬", "Singapore"),
    "HK": ("🇭🇰", "Hong Kong"),
    "RU": ("🇷🇺", "Russia"),
    "UA": ("🇺🇦", "Ukraine"),
    "BY": ("🇧🇾", "Belarus"),
}


# ==================================================
# BASE64
# ==================================================

def decode_b64(value):
    value = value.strip()
    value += "=" * (-len(value) % 4)

    decoded = base64.b64decode(
        value,
        altchars=b"-_",
        validate=True
    )

    return decoded.decode("utf-8")


# ==================================================
# TLS
# ==================================================

def tls_config(params, default_server_name=""):

    security = params.get(
        "security", [""]
    )[0].lower()

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
        tls["alpn"] = [
            item.strip()
            for item in alpn.split(",")
            if item.strip()
        ]

    insecure = params.get(
        "allowInsecure",
        params.get("insecure", ["false"])
    )[0].lower()

    if insecure in ("1", "true", "yes"):
        tls["insecure"] = True

    fingerprint = params.get("fp", [""])[0]

    if fingerprint:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fingerprint
        }

    if security == "reality":

        public_key = (
            params.get("pbk", [""])[0]
            or params.get("publicKey", [""])[0]
        )

        short_id = (
            params.get("sid", [""])[0]
            or params.get("shortId", [""])[0]
        )

        if not public_key:
            raise ValueError(
                "Reality: missing public key"
            )

        tls["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": short_id
        }

    return {"tls": tls}


# ==================================================
# TRANSPORT
# ==================================================

def transport_config(params):

    kind = params.get(
        "type", ["tcp"]
    )[0].lower()

    if kind in ("tcp", ""):
        return {}

    if kind == "ws":

        path = params.get("path", ["/"])[0]
        host = params.get("host", [""])[0]

        result = {
            "type": "ws",
            "path": path,
            "headers": {}
        }

        if host:
            result["headers"]["Host"] = host

        early_data = params.get("ed", ["0"])[0]

        try:
            if int(early_data) > 0:
                result["max_early_data"] = int(early_data)
                result["early_data_header_name"] = (
                    params.get("eh", [""])[0]
                )
        except ValueError:
            pass

        return {"transport": result}

    if kind == "grpc":

        service = (
            params.get("serviceName", [""])[0]
            or params.get("service_name", [""])[0]
        )

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

    if kind in ("http", "h2"):

        host = params.get("host", [""])[0]

        result = {
            "type": "http",
            "path": params.get("path", ["/"])[0]
        }

        if host:
            result["host"] = [host]

        return {"transport": result}

    if kind == "quic":

        return {
            "transport": {
                "type": "quic"
            }
        }

    raise ValueError(
        f"Unsupported transport: {kind}"
    )


# ==================================================
# VMESS
# ==================================================

def parse_vmess(link):

    raw = link[len("vmess://"):].strip()

    data = json.loads(decode_b64(raw))

    host = data.get("add")
    port = int(data.get("port"))
    uuid = data.get("id")

    if not host or not port or not uuid:
        raise ValueError(
            "Invalid VMess configuration"
        )

    network = data.get("net", "tcp").lower()

    params = {
        "security": [data.get("tls", "")],
        "sni": [
            data.get("sni")
            or data.get("host", "")
        ],
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


# ==================================================
# SHADOWSOCKS
# ==================================================

def parse_ss(link):

    parsed = urlsplit(link)

    if parsed.hostname and parsed.port:

        host = parsed.hostname
        port = parsed.port

        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")

        if not password:

            decoded = decode_b64(username)

            if ":" not in decoded:
                raise ValueError(
                    "Invalid Shadowsocks credentials"
                )

            method, password = decoded.split(":", 1)

        else:
            method = username

        params = parse_qs(parsed.query)

    else:

        raw = link[len("ss://"):]

        decoded = decode_b64(
            raw.split("#", 1)[0]
        )

        if "@" not in decoded:
            raise ValueError(
                "Unsupported Shadowsocks format"
            )

        credentials, address = decoded.rsplit("@", 1)

        if ":" not in credentials:
            raise ValueError(
                "Invalid Shadowsocks credentials"
            )

        method, password = credentials.split(":", 1)

        address_parsed = urlsplit("//" + address)

        host = address_parsed.hostname
        port = address_parsed.port
        params = {}

    if not host or not port or not method or not password:
        raise ValueError(
            "Incomplete Shadowsocks configuration"
        )

    outbound = {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password
    }

    plugin = params.get("plugin", [""])[0]

    if plugin:

        plugin_name, _, plugin_options = plugin.partition(";")

        if plugin_name not in (
            "obfs-local",
            "v2ray-plugin"
        ):
            raise ValueError(
                f"Unsupported SS plugin: {plugin_name}"
            )

        outbound["plugin"] = plugin_name
        outbound["plugin_opts"] = plugin_options

    return outbound


# ==================================================
# MAIN LINK PARSER
# ==================================================

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
        raise ValueError(
            "Missing server address or port"
        )

    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    if scheme == "vless":

        if not username:
            raise ValueError("VLESS: missing UUID")

        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": username
        }

        flow = params.get("flow", [""])[0]

        if flow:
            outbound["flow"] = flow

        packet_encoding = params.get(
            "packetEncoding", [""]
        )[0]

        if packet_encoding:
            outbound["packet_encoding"] = packet_encoding

        outbound.update(tls_config(params, host))
        outbound.update(transport_config(params))

        return outbound

    if scheme == "trojan":

        secret = password or username

        if not secret:
            raise ValueError("Trojan: missing password")

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

        if not secret:
            raise ValueError(
                "Hysteria2: missing password"
            )

        tls = {
            "enabled": True,
            "server_name": params.get(
                "sni", [host]
            )[0]
        }

        insecure = params.get(
            "insecure", ["0"]
        )[0].lower()

        if insecure in ("1", "true", "yes"):
            tls["insecure"] = True

        alpn = params.get("alpn", [""])[0]

        if alpn:
            tls["alpn"] = [
                item.strip()
                for item in alpn.split(",")
                if item.strip()
            ]

        outbound = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "password": secret,
            "tls": tls
        }

        obfs = params.get("obfs", [""])[0]
        obfs_password = params.get(
            "obfs-password", [""]
        )[0]

        if obfs:
            outbound["obfs"] = {
                "type": obfs,
                "password": obfs_password
            }

        return outbound

    raise ValueError(
        f"Unsupported protocol: {scheme}"
    )


# ==================================================
# SERVER INFORMATION
# ==================================================

def get_server_info(outbound):

    return {
        "protocol": outbound["type"],
        "host": outbound["server"],
        "port": outbound["server_port"]
    }


# ==================================================
# LOCAL PORT
# ==================================================

def get_free_port():

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as sock:

        sock.bind(("127.0.0.1", 0))

        return sock.getsockname()[1]


def wait_for_port(port, process):

    deadline = time.time() + START_TIMEOUT

    while time.time() < deadline:

        if process.poll() is not None:
            return False

        try:

            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.5
            ):
                return True

        except OSError:
            time.sleep(0.25)

    return False


# ==================================================
# IP AND COUNTRY CHECK
# ==================================================

def check_ip(proxy):

    result = {
        "ip": None,
        "country": None,
        "country_code": None
    }

    proxies = {
        "http": proxy,
        "https": proxy
    }

    session = requests.Session()
    session.trust_env = False

    try:

        response = session.get(
            IP_URL,
            proxies=proxies,
            timeout=TIMEOUT
        )

        response.raise_for_status()

        data = response.json()

        if data.get("success") is not False:

            result["ip"] = data.get("ip")
            result["country"] = data.get("country")
            result["country_code"] = data.get(
                "country_code"
            )

    except (requests.RequestException, ValueError):
        pass

    finally:
        session.close()

    return result


# ==================================================
# SERVER RENAMING
# ==================================================

def make_server_name(outbound, country_code=None):

    protocol = outbound["type"].upper()
    port = outbound["server_port"]

    if country_code:

        flag, country = COUNTRIES.get(
            country_code.upper(),
            ("🌍", country_code.upper())
        )

        return (
            f"{flag} {country} | "
            f"{protocol} | {port}"
        )

    return (
        f"🌐 Unknown | "
        f"{protocol} | {port}"
    )


def rename_link(link, new_name):

    parsed = urlsplit(link)

    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.query,
        quote(new_name, safe="")
    ))


# ==================================================
# CHECK ENDPOINT
# ==================================================

def test_endpoint(session, url, proxies):

    for attempt in range(RETRIES):

        try:

            response = session.get(
                url,
                proxies=proxies,
                timeout=TIMEOUT,
                allow_redirects=False
            )

            if response.status_code == 204:
                return True

        except requests.RequestException:
            pass

        if attempt + 1 < RETRIES:
            time.sleep(RETRY_DELAY)

    return False


# ==================================================
# CHECK ONE CONFIGURATION
# ==================================================

def check_link(link):

    results = {
        "working": False,
        "cloudflare": False,
        "google": False,
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

        info = get_server_info(outbound)

        results.update(info)

        port = get_free_port()

        config = {
            "log": {
                "level": "error"
            },

            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "local-in",
                    "listen": "127.0.0.1",
                    "listen_port": port
                }
            ],

            "outbounds": [
                outbound,
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ],

            "route": {
                "final": "proxy"
            }
        }

        with tempfile.TemporaryDirectory() as directory:

            config_path = (
                Path(directory) / "config.json"
            )

            config_path.write_text(
                json.dumps(config, ensure_ascii=False),
                encoding="utf-8"
            )

            try:

                subprocess.run(
                    [
                        SING_BOX,
                        "check",
                        "-c",
                        str(config_path)
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=15
                )

            except subprocess.CalledProcessError as error:

                message = (
                    error.stderr or error.stdout or str(error)
                )

                raise RuntimeError(
                    "sing-box config error: "
                    + message[:180]
                )

            process = subprocess.Popen(
                [
                    SING_BOX,
                    "run",
                    "-c",
                    str(config_path)
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            try:

                if not wait_for_port(port, process):
                    raise RuntimeError(
                        "sing-box did not start"
                    )

                proxy = f"http://127.0.0.1:{port}"

                proxies = {
                    "http": proxy,
                    "https": proxy
                }

                # Independent endpoint checks

                results["cloudflare"] = test_endpoint(
                    session,
                    TEST_URLS["cloudflare"],
                    proxies
                )

                results["google"] = test_endpoint(
                    session,
                    TEST_URLS["google"],
                    proxies
                )

                # IP check is informational

                if results["cloudflare"] or results["google"]:

                    ip_info = check_ip(proxy)

                    results.update(ip_info)

                results["working"] = (
                    results["cloudflare"]
                    or results["google"]
                )

                results["server_name"] = make_server_name(
                    outbound,
                    results["country_code"]
                )

            finally:

                if process and process.poll() is None:

                    process.terminate()

                    try:
                        process.wait(timeout=3)

                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

                    process = None

    except FileNotFoundError:

        results["error"] = (
            "sing-box executable not found"
        )

    except subprocess.TimeoutExpired:

        results["error"] = (
            "sing-box operation timed out"
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
                process.wait()

        session.close()

    return results

# ==================================================
# TEST RUN
# ==================================================

if __name__ == "__main__":

    print("=" * 45)
    print("FLOGGER VPN CHECKER")
    print("=" * 45)

    print("Checker module loaded successfully.")
    print("sing-box:", shutil.which("sing-box") or "not found")

    print("=" * 45)
    
