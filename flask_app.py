"""
BLS Selfie Relay - v6.2
- Contourne Cloudflare via curl_cffi (TLS fingerprint Chrome)
- Fallback automatique vers requests si curl_cffi indisponible
- Proxy résidentiel optionnel
- Réinjection des cookies ET du header Authorization côté serveur
- FIX: upload multipart via CurlMime pour curl_cffi (compat multi-versions)
"""

from flask import Flask, send_from_directory, request, jsonify
from pathlib import Path
import threading
import time
import os

app = Flask(__name__)

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

BASE_DIR = Path(__file__).resolve().parent

SESSION_TTL = 30 * 60
sessions = {}
sessions_lock = threading.Lock()

LIVENESS_UPSTREAM = "https://api-liveness-algeria.blsinternational.com"
BLS_ORIGIN = "https://algeria.blsinternational.com"

# HTTP CLIENT - curl_cffi (TLS fingerprint Chrome)
USE_CURL_CFFI = False
CurlMime = None

try:
    import curl_cffi
    from curl_cffi import requests as http_requests
    USE_CURL_CFFI = True

    # CurlMime peut être dans curl_cffi.requests OU curl_cffi selon la version
    CurlMime = getattr(http_requests, "CurlMime", None) or getattr(curl_cffi, "CurlMime", None)

    version = getattr(curl_cffi, "__version__", "?")
    app.logger.info(
        "[INIT] curl_cffi charge (v%s, TLS fingerprint Chrome) | CurlMime=%s",
        version, "OK" if CurlMime else "ABSENT",
    )
    if not CurlMime:
        app.logger.warning(
            "[INIT] CurlMime introuvable - mise a jour requise: pip install -U curl_cffi"
        )
except ImportError:
    import requests as http_requests
    USE_CURL_CFFI = False
    app.logger.warning("[INIT] curl_cffi absent - fallback requests")

RESIDENTIAL_PROXY = os.environ.get("RESIDENTIAL_PROXY", "").strip()
if RESIDENTIAL_PROXY:
    app.logger.info("[INIT] Proxy residentiel: active")
else:
    app.logger.info("[INIT] Proxy residentiel: aucun")


def _proxies_dict():
    if RESIDENTIAL_PROXY:
        return {"http": RESIDENTIAL_PROXY, "https": RESIDENTIAL_PROXY}
    return None


def _http_post(url, **kwargs):
    if USE_CURL_CFFI:
        kwargs.setdefault("impersonate", "chrome")
        kwargs.setdefault("verify", False)
    return http_requests.post(url, **kwargs)


def _cleanup_sessions():
    now = time.time()
    with sessions_lock:
        expired = [
            phone for phone, data in sessions.items()
            if now - data.get("timestamp", 0) > SESSION_TTL
        ]
        for phone in expired:
            sessions.pop(phone, None)


def _split_auth_data(raw):
    if not isinstance(raw, dict):
        return {}, None
    cookies = {}
    authorization = None
    for k, v in raw.items():
        if k == "__authorization__":
            authorization = v
        elif k.startswith("__") and k.endswith("__"):
            continue
        else:
            cookies[k] = v
    return cookies, authorization


def _find_session_auth(appointment_id, fingerprint):
    _cleanup_sessions()
    target_app = str(appointment_id).strip()
    target_fp = str(fingerprint).strip()

    with sessions_lock:
        if not sessions:
            app.logger.warning("[_find_session_auth] AUCUNE session | app_id=%s", target_app)
            return None

        for phone, data in sessions.items():
            stored_app = str(data.get("appointment_id") or "").strip()
            stored_fp = str(data.get("fingerprint") or "").strip()
            if stored_app == target_app and stored_fp == target_fp:
                raw = data.get("session_cookies") or {}
                cookies, authorization = _split_auth_data(raw)
                app.logger.info(
                    "[_find_session_auth] TROUVE | phone=%s | cookie_names=%s | auth=%s",
                    phone, list(cookies.keys()), "oui" if authorization else "non"
                )
                return {"cookies": cookies, "authorization": authorization}

    return None


@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, x-device-fingerprint, x-lang, Accept, ngrok-skip-browser-warning"
    )
    response.headers["Access-Control-Max-Age"] = "600"
    return response


@app.route("/api/liveness/<path:_>", methods=["OPTIONS"])
def cors_preflight(_):
    return ("", 204)


@app.route("/")
def home():
    tls_status = "curl_cffi (Chrome TLS) OK" if USE_CURL_CFFI else "requests standard"
    proxy_status = "active" if RESIDENTIAL_PROXY else "aucun"
    mime_status = "OK" if CurlMime else "ABSENT (pip install -U curl_cffi)"
    return f"""
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Selfie Relay</title>
      </head>
      <body style="font-family:sans-serif;text-align:center;padding:40px;background:#0a0a1a;color:#fff">
        <h1>Selfie Relay</h1>
        <p>Ouvre la page selfie depuis ton telephone.</p>
        <a href="/selfie" style="color:#4caf50;font-size:1.2em">Page Selfie</a>
        <p style="margin-top:30px;color:#888;font-size:.85em">
          TLS: {tls_status}<br>
          CurlMime: {mime_status}<br>
          Proxy residentiel: {proxy_status}
        </p>
      </body>
    </html>
    """


@app.route("/selfie")
@app.route("/selfie_mobile.html")
def selfie_page():
    return send_from_directory(BASE_DIR, "selfie_mobile_fixed.html")


@app.post("/api/push")
def push_session():
    try:
        data = request.get_json(silent=True)
    except Exception as e:
        app.logger.exception("[push] JSON parse error")
        return jsonify(error="invalid json"), 400

    if not isinstance(data, dict):
        return jsonify(error="JSON object required"), 400

    try:
        phone = str(data.get("phone", "") or "").strip()
        appointment_id = str(data.get("appointment_id", "") or "").strip()
        fingerprint = str(data.get("fingerprint", "") or "").strip()
        email = str(data.get("email", "") or "").strip()
        raw_cookies = data.get("session_cookies") or {}

        if not isinstance(raw_cookies, dict):
            raw_cookies = {}

        session_cookies = {
            str(k): str(v) for k, v in raw_cookies.items() if k and v is not None
        }

        if not phone or not appointment_id or not fingerprint:
            return jsonify(error="phone, appointment_id and fingerprint required"), 400

        with sessions_lock:
            sessions[phone] = {
                "appointment_id": appointment_id,
                "fingerprint": fingerprint,
                "email": email,
                "session_cookies": session_cookies,
                "timestamp": time.time(),
            }

        cookies, authorization = _split_auth_data(session_cookies)
        has_bls = bool(cookies) or bool(authorization)

        app.logger.info(
            "[push] phone=%s | app=%s | cookie_names=%s | auth=%s",
            phone, appointment_id, list(cookies.keys()),
            "oui" if authorization else "non"
        )

        return jsonify(
            status="ok",
            phone=phone,
            has_session_cookie=has_bls,
            cookie_names=list(cookies.keys()),
            has_authorization=bool(authorization),
        )
    except Exception as e:
        app.logger.exception("[push] unexpected error")
        return jsonify(error="internal"), 500


@app.get("/api/pull/<phone>")
def pull_session(phone):
    _cleanup_sessions()
    phone = str(phone).strip()
    with sessions_lock:
        data = sessions.get(phone)
    if not data:
        return jsonify(status="not_found"), 404
    return jsonify(
        status="ok",
        data={
            "appointment_id": data["appointment_id"],
            "fingerprint": data["fingerprint"],
            "email": data.get("email", ""),
        },
    )


@app.get("/api/status")
def api_status():
    _cleanup_sessions()
    with sessions_lock:
        phones = list(sessions.keys())
        info = {}
        for phone, d in sessions.items():
            cookies, authorization = _split_auth_data(d.get("session_cookies") or {})
            info[phone] = {
                "appointment_id": d.get("appointment_id"),
                "has_session_cookie": bool(cookies) or bool(authorization),
                "cookie_names": list(cookies.keys()),
                "has_authorization": bool(authorization),
            }
    return jsonify(
        sessions=len(phones),
        phones=phones,
        info=info,
        curl_cffi=USE_CURL_CFFI,
        curl_mime=bool(CurlMime),
        residential_proxy=bool(RESIDENTIAL_PROXY),
    )


def _forward_headers(request_obj, extra=None):
    ua = request_obj.headers.get("User-Agent") or ""
    if not ua or "curl" in ua.lower() or "python" in ua.lower():
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/153.0.0.0 Safari/537.36"
        )
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "fr",
        "x-lang": "fr",
        "Origin": BLS_ORIGIN,
        "Referer": BLS_ORIGIN + "/",
        "User-Agent": str(ua),
    }
    if extra:
        for k, v in extra.items():
            headers[k] = str(v)
    return headers


@app.post("/api/liveness/device-info")
def proxy_device_info():
    try:
        appointment_id = request.args.get("appointment_id", "").strip()
        if not appointment_id:
            return jsonify(error="appointment_id required"), 400

        fp = request.headers.get("x-device-fingerprint", "").strip()
        if not fp:
            return jsonify(error="x-device-fingerprint required"), 400

        auth_data = _find_session_auth(appointment_id, fp)
        if not auth_data:
            return jsonify(error="no_session"), 401

        session_cookies = auth_data["cookies"]
        authorization = auth_data["authorization"]

        body = request.get_json(silent=True) or {}

        headers = _forward_headers(request, {
            "Content-Type": "application/json",
            "x-device-fingerprint": fp,
        })
        if authorization:
            headers["Authorization"] = authorization

        proxies = _proxies_dict()
        app.logger.info(
            "[device-info] upstream | cookies=%s | auth=%s | proxy=%s | curl_cffi=%s",
            list(session_cookies.keys()),
            "oui" if authorization else "non",
            "residentiel" if proxies else "aucun",
            USE_CURL_CFFI,
        )

        r = _http_post(
            LIVENESS_UPSTREAM + "/device-info",
            params={"appointment_id": appointment_id},
            json=body,
            headers=headers,
            cookies=session_cookies,
            proxies=proxies,
            timeout=30,
        )
        app.logger.info("[device-info] upstream HTTP %s", r.status_code)

        if r.status_code == 403:
            app.logger.warning("[device-info] 403 BODY: %s", r.text[:300])

        return (
            r.content,
            r.status_code,
            {"Content-Type": r.headers.get("Content-Type", "application/json")},
        )
    except Exception as e:
        app.logger.exception("[device-info] error")
        return jsonify(error="internal", detail=str(e)[:200]), 500


@app.post("/api/liveness/verify-face")
def proxy_verify_face():
    try:
        appointment_id = request.args.get("appointment_id", "").strip()
        if not appointment_id:
            return jsonify(error="appointment_id required"), 400

        fp = request.headers.get("x-device-fingerprint", "").strip()
        if not fp:
            return jsonify(error="x-device-fingerprint required"), 400

        auth_data = _find_session_auth(appointment_id, fp)
        if not auth_data:
            return jsonify(error="no_session"), 401

        session_cookies = auth_data["cookies"]
        authorization = auth_data["authorization"]

        if "captured_image" not in request.files:
            return jsonify(error="captured_image file required"), 400

        file = request.files["captured_image"]
        file_bytes = file.read()
        if not file_bytes:
            return jsonify(error="empty file"), 400

        headers = _forward_headers(request, {"x-device-fingerprint": fp})
        if authorization:
            headers["Authorization"] = authorization

        proxies = _proxies_dict()
        app.logger.info(
            "[verify-face] upstream | cookies=%s | auth=%s | proxy=%s | curl_cffi=%s | img_bytes=%d",
            list(session_cookies.keys()),
            "oui" if authorization else "non",
            "residentiel" if proxies else "aucun",
            USE_CURL_CFFI,
            len(file_bytes),
        )

        use_mime = USE_CURL_CFFI and CurlMime is not None

        if use_mime:
            # curl_cffi: multipart via CurlMime (files= non supporté)
            mp = CurlMime()
            mp.addpart(
                name="captured_image",
                content_type=file.mimetype or "image/jpeg",
                filename=file.filename or "selfie.jpg",
                data=file_bytes,
            )
            try:
                r = http_requests.post(
                    LIVENESS_UPSTREAM + "/verify-face",
                    params={"appointment_id": appointment_id},
                    multipart=mp,
                    headers=headers,
                    cookies=session_cookies,
                    proxies=proxies,
                    impersonate="chrome",
                    verify=False,
                    timeout=90,
                )
            finally:
                mp.close()
        else:
            # requests standard (ou curl_cffi sans CurlMime) : files= supporté
            if USE_CURL_CFFI and not CurlMime:
                app.logger.warning(
                    "[verify-face] CurlMime absent - fallback files= (peut echouer sur curl_cffi)"
                )
            files = {
                "captured_image": (
                    file.filename or "selfie.jpg",
                    file_bytes,
                    file.mimetype or "image/jpeg",
                )
            }
            post_kwargs = dict(
                params={"appointment_id": appointment_id},
                files=files,
                headers=headers,
                cookies=session_cookies,
                proxies=proxies,
                timeout=90,
            )
            if USE_CURL_CFFI:
                post_kwargs["impersonate"] = "chrome"
                post_kwargs["verify"] = False
            r = http_requests.post(
                LIVENESS_UPSTREAM + "/verify-face",
                **post_kwargs,
            )

        app.logger.info("[verify-face] upstream HTTP %s", r.status_code)

        if r.status_code == 403:
            app.logger.warning("[verify-face] 403 BODY: %s", r.text[:300])

        return (
            r.content,
            r.status_code,
            {"Content-Type": r.headers.get("Content-Type", "application/json")},
        )
    except Exception as e:
        app.logger.exception("[verify-face] error")
        return jsonify(error="internal", detail=str(e)[:200]), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host="0.0.0.0", port=port, debug=debug)
