import base64
import json
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote, quote

import requests


# ==================================================
# FLOGGER VPN CHECKER (Strict Validation & Clean Names v8.2)
# ==================================================

VERSION = "8.2"

TEST_URLS = {
    "google": "https://www.gstatic.com/generate_204",
}

IP_URL = "http://ip-api.com/json/?fields=status,message,country,countryCode,query"

TIMEOUT = 10
START_TIMEOUT = 6
RETRIES = 2
RETRY_DELAY = 1

SING_BOX = "sing-box"

# Русские названия стран. Для остальных стран флаг строится автоматически
COUNTRIES = {
    "DE": ("🇩🇪", "Германия"),
    "RU": ("🇷🇺", "Россия"),
    "US": ("🇺🇸", "США"),
    "PL": ("🇵🇱", "Польша"),
    "NL": ("🇳🇱", "Нидерланды"),
    "FR": ("🇫🇷", "Франция"),
    "MF": ("🇲🇫", "Сен-Мартен"),
    "UA": ("🇺🇦", "Украина"),
    "TR": ("🇹🇷", "Турция"),
    "RS": ("🇷🇸", "Сербия"),
    "NO": ("🇳🇴", "Норвегия"),
    "MX": ("🇲🇽", "Мексика"),
    "LV": ("🇱🇻", "Латвия"),
    "IR": ("🇮🇷", "Иран"),
    "FI": ("🇫🇮", "Финляндия"),
    "EE": ("🇪🇪", "Эстония"),
    "CZ": ("🇨🇿", "Чехия"),
    "DK": ("🇩🇰", "Дания"),
    "BY": ("🇧🇾", "Беларусь"),
    "CN": ("🇨🇳", "Китай"),
    "BG": ("🇧🇬", "Болгария"),
    "AT": ("🇦🇹", "Австрия"),
    "JP": ("🇯🇵", "Япония"),
    "LT": ("🇱🇹", "Литва"),
    "CH": ("🇨🇭", "Швейцария"),
    "RO": ("🇷🇴", "Румыния"),
    "MD": ("🇲🇩", "Молдова"),
    "CY": ("🇨🇾", "Кипр"),
    "GB": ("🇬🇧", "Великобритания"),
    "KR": ("🇰🇷", "Южная Корея"),
    "CA": ("🇨🇦", "Канада"),
    "NE": ("🇳🇪", "Нигер"),
    "BR": ("🇧🇷", "Бразилия"),
    "AU": ("🇦🇺", "Австралия"),
    "IT": ("🇮🇹", "Италия"),
    "ES": ("🇪🇸", "Испания"),
    "SE": ("🇸🇪", "Швеция"),
    "SG": ("🇸🇬", "Сингапур"),
    "HK": ("🇭🇰", "Гонконг"),
    "IN": ("🇮🇳", "Индия"),
    "IL": ("🇮🇱", "Израиль"),
    "KZ": ("🇰🇿", "Казахстан"),
    "GE": ("🇬🇪", "Грузия"),
    "AM": ("🇦🇲", "Армения"),
    "AZ": ("🇦🇿", "Азербайджан"),
    "HU": ("🇭🇺", "Венгрия"),
    "SK": ("🇸🇰", "Словакия"),
    "BE": ("🇧🇪", "Бельгия"),
    "IE": ("🇮🇪", "Ирландия"),
    "PT": ("🇵🇹", "Португалия"),
    "GR": ("🇬🇷", "Греция"),
    "AE": ("🇦🇪", "ОАЭ"),
    "TW": ("🇹🇼", "Тайвань"),
}


# ---------- вспомогательные функции ----------

def decode_b64(value):
    value = (value or "").strip()
    value += "=" * (-len(value) % 4)
    for altchars in (b"-_", b"+/"):
        try:
            decoded = base64.b64decode(value, altchars=altchars, validate=False)
            return decoded.decode("utf-8", errors="ignore")
        except Exception:
            continue
    return ""


def first(params, *keys, default=""):
    """Первое непустое значение параметра из нескольких возможных ключей"""
    for key in keys:
        values = params.get(key)
        if values and values[0]:
            return values[0]
    return default


def is_true(value):
    return str(value).strip().lower() in ("1", "true", "yes")


def check_port(port):
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    return port


def country_flag(code):
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


def country_label(code, api_name=None):
    if not code:
        return None
    code = code.upper()
    if code in COUNTRIES:
        return COUNTRIES[code]
    if re.fullmatch(r"[A-Z]{2}", code):
        return country_flag(code), api_name or code
    return None


# ---------- TLS / транспорт ----------

def tls_config(params, default_server_name=""):
    security = first(params, "security").lower()
    if security not in ("tls", "reality"):
        return {}

    sni = first(params, "sni", "serverName") or default_server_name
    tls = {"enabled": True}
    if sni:
        tls["server_name"] = sni

    alpn = first(params, "alpn")
    if alpn:
        tls["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]

    if is_true(first(params, "allowInsecure", "insecure", default="false")):
        tls["insecure"] = True

    fingerprint = first(params, "fp")

    if security == "reality":
        public_key = first(params, "pbk", "publicKey", "pk")
        if not public_key:
            raise ValueError("Reality without public key")
        tls["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": first(params, "sid", "shortId")
        }
        # для Reality uTLS обязателен
        fingerprint = fingerprint or "chrome"

    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

    return {"tls": tls}


def transport_config(params):
    kind = first(params, "type", default="tcp").lower()
    if kind in ("tcp", "raw", "none"):
        return {}

    path = first(params, "path", default="/")
    host = first(params, "host")

    if kind == "ws":
        result = {"type": "ws", "path": path, "headers": {}}
        if host:
            result["headers"]["Host"] = host
        return {"transport": result}

    if kind == "grpc":
        service = first(params, "serviceName", "service_name")
        return {"transport": {"type": "grpc", "service_name": service}}

    if kind == "httpupgrade":
        result = {"type": "httpupgrade", "path": path}
        if host:
            result["host"] = host
        return {"transport": result}

    if kind in ("http", "h2"):
        result = {"type": "http", "path": path}
        if host:
            result["host"] = [host]
        return {"transport": result}

    if kind == "quic":
        return {"transport": {"type": "quic"}}

    # xhttp / splithttp / kcp и прочее sing-box не поддерживает.
    # Раньше такие конфиги молча превращались в TCP и не работали.
    raise ValueError(f"Unsupported transport: {kind}")


# ---------- парсеры ссылок ----------

def parse_vmess(link):
    raw = link[len("vmess://"):].split("#", 1)[0].strip()
    decoded_json = decode_b64(raw)
    if not decoded_json:
        raise ValueError("Invalid VMess base64")
    data = json.loads(decoded_json)

    host = data.get("add")
    uuid = data.get("id")
    if not host or not uuid or not data.get("port"):
        raise ValueError("Invalid VMess configuration")
    port = check_port(data.get("port"))

    network = (data.get("net") or "tcp").lower()
    path = data.get("path") or "/"
    params = {
        "security": [data.get("tls") or ""],
        "sni": [data.get("sni") or data.get("host") or ""],
        "type": [network],
        "path": [path],
        "host": [data.get("host") or ""],
        "fp": [data.get("fp") or ""],
        "alpn": [data.get("alpn") or ""],
        "serviceName": [data.get("path") or ""]
    }

    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "security": data.get("scy") or "auto",
        "alter_id": int(data.get("aid") or 0)
    }
    outbound.update(tls_config(params, host))
    outbound.update(transport_config(params))
    return outbound


def parse_ss(link):
    parsed = urlsplit(link)
    params = parse_qs(parsed.query)
    if first(params, "plugin"):
        raise ValueError("Shadowsocks plugins are not supported")

    if parsed.hostname and parsed.port:
        host = parsed.hostname
        port = check_port(parsed.port)
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if not password:
            decoded = decode_b64(username)
            if ":" not in decoded:
                raise ValueError("Unsupported Shadowsocks format")
            method, password = decoded.split(":", 1)
        else:
            method = username
    else:
        raw = link[len("ss://"):].split("#", 1)[0].split("?", 1)[0]
        decoded = decode_b64(raw)
        if "@" not in decoded:
            raise ValueError("Unsupported Shadowsocks format")
        credentials, address = decoded.rsplit("@", 1)
        if ":" not in credentials:
            raise ValueError("Unsupported Shadowsocks format")
        method, password = credentials.split(":", 1)
        address_parsed = urlsplit("//" + address)
        host = address_parsed.hostname
        if not host or not address_parsed.port:
            raise ValueError("Missing server address or port")
        port = check_port(address_parsed.port)

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

    if not host or not parsed.port:
        raise ValueError("Missing server address or port")
    port = check_port(parsed.port)

    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")

    if scheme == "vless":
        if not username:
            raise ValueError("VLESS without UUID")
        # VLESS encryption (post-quantum) sing-box не поддерживает
        if first(params, "encryption", default="none").lower() != "none":
            raise ValueError("VLESS encryption is not supported")
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": username
        }
        flow = first(params, "flow")
        if flow:
            outbound["flow"] = flow
        outbound.update(tls_config(params, host))
        outbound.update(transport_config(params))
        return outbound

    if scheme == "trojan":
        secret = password or username
        if not secret:
            raise ValueError("Trojan without password")
        tls_params = dict(params)
        if first(params, "security").lower() != "reality":
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
            raise ValueError("Hysteria2 without password")
        tls = {"enabled": True, "server_name": first(params, "sni") or host}
        if is_true(first(params, "insecure", "allowInsecure", default="0")):
            tls["insecure"] = True
        alpn = first(params, "alpn")
        if alpn:
            tls["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]

        outbound = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "password": secret,
            "tls": tls
        }
        obfs = first(params, "obfs").lower()
        if obfs:
            if obfs != "salamander":
                raise ValueError(f"Unsupported obfs: {obfs}")
            outbound["obfs"] = {
                "type": "salamander",
                "password": first(params, "obfs-password", "obfs_password")
            }
        return outbound

    raise ValueError(f"Unsupported protocol: {scheme}")


# ---------- sing-box и проверки ----------

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


def stop_process(process):
    """Корректно останавливает sing-box, при необходимости убивает"""
    if not process or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


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
            code = (data.get("countryCode") or "").upper()
            if re.fullmatch(r"[A-Z]{2}", code):
                result["country_code"] = code
    except Exception:
        pass
    finally:
        session.close()
    return result


def make_server_name(outbound, country_code=None, country_name=None):
    protocol = outbound["type"].upper()
    label = country_label(country_code, country_name)
    if label:
        flag, country = label
        return f"{flag} {country} | {protocol}"
    return f"🌐 Неизвестно | {protocol}"


def rename_link(link, name):
    """Заменяет старое имя в ссылке на чистое"""
    if link.lower().startswith("vmess://"):
        # у vmess имя хранится внутри base64-JSON (поле ps)
        try:
            raw = link[len("vmess://"):].split("#", 1)[0]
            data = json.loads(decode_b64(raw))
            data["ps"] = name
            encoded = base64.b64encode(json.dumps(data, ensure_ascii=False).encode("utf-8")).decode("ascii")
            return "vmess://" + encoded
        except Exception:
            pass
    base_link = link.split("#", 1)[0]
    return f"{base_link}#{quote(name)}"


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
        "google": False,
        "ping": None,
        "ip": None,
        "country": None,
        "country_code": None,
        "server_name": None,
        "link": link,
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

        # Блок "dns" убран: старый формат устарел и ломает запуск
        # в новых версиях sing-box. Достаточно системного DNS.
        config = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "local-in", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": "proxy"}
        }

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

            try:
                process = subprocess.Popen(
                    [SING_BOX, "run", "-c", str(config_path)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except FileNotFoundError:
                raise RuntimeError("sing-box not found (check SING_BOX path)")

            try:
                if not wait_for_port(port, process):
                    raise RuntimeError("sing-box did not start")

                proxy = f"http://127.0.0.1:{port}"
                proxies = {"http": proxy, "https": proxy}

                success, ping = test_endpoint(session, TEST_URLS["google"], proxies)
                results["working"] = success
                results["google"] = success
                results["ping"] = ping

                if success:
                    results.update(check_ip(proxy))

                results["server_name"] = make_server_name(
                    outbound, results.get("country_code"), results.get("country")
                )
                # ссылку переименовываем только если страна известна
                if results.get("country_code"):
                    results["link"] = rename_link(link, results["server_name"])
            finally:
                stop_process(process)
    except Exception as error:
        results["error"] = str(error)[:250]
    finally:
        stop_process(process)
        session.close()

    return results
