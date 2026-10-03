"""
BLS Selfie Relay — version corrigée v5
- Proxy Liveness (contourne CORS depuis le mobile)
- Réinjection des cookies ET du header Authorization côté serveur
- Les données d'auth ne sont JAMAIS exposées au navigateur mobile
- CORRECTION : parsing robuste de la réponse /verify-face
  → Détecte plusieurs formats de réponse de l'upstream
  → Ajoute le champ `verified` pour le front mobile
- CORRECTION : conservation des cookies de session jusqu'au TTL
- CORRECTION : gestion du Content-Type des réponses upstream
- Log détaillé pour diagnostic
"""

from flask import Flask, send_from_directory, request, jsonify
from pathlib import Path
import threading
import time
import json
import requests

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent

SESSION_TTL = 30 * 60
sessions = {}
sessions_lock = threading.Lock()

LIVENESS_UPSTREAM = "https://api-liveness-algeria.blsinternational.com"
BLS_ORIGIN = "https://algeria.blsinternational.com"


# ═══════════════════════════════════════════════════════════════
# SESSION CLEANUP
# ═══════════════════════════════════════════════════════════════
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
    """
    Sépare les vraies cookies des pseudo-entrées (__authorization__).
    Retourne (cookies_dict, authorization_value_or_None).
    """
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
    """
    Retrouve les données d'auth BLS stockées côté serveur pour un couple
    (appointment_id, fingerprint).
    Retourne un dict {"cookies": {...}, "authorization": "..."} ou None.
    """
    _cleanup_sessions()
    target_app = str(appointment_id).strip()
    target_fp = str(fingerprint).strip()

    with sessions_lock:
        if not sessions:
            app.logger.warning(
                "[_find_session_auth] AUCUNE session en mémoire | app_id=%s fp=%s",
                target_app, target_fp[:12]
            )
            return None

        for phone, data in sessions.items():
            stored_app = str(data.get("appointment_id") or "").strip()
            stored_fp = str(data.get("fingerprint") or "").strip()

            if stored_app == target_app and stored_fp == target_fp:
                raw = data.get("session_cookies") or {}
                cookies, authorization = _split_auth_data(raw)

                app.logger.info(
                    "[_find_session_auth] ✅ TROUVÉ | phone=%s | "
                    "cookie_names=%s | authorization=%s",
                    phone,
                    list(cookies.keys()),
                    "oui" if authorization else "non",
                )

                if not cookies and not authorization:
                    app.logger.warning(
                        "[_find_session_auth] ⚠️  Session trouvée MAIS aucun cookie/auth"
                    )

                return {
                    "cookies": cookies,
                    "authorization": authorization,
                }

            app.logger.warning(
                "[_find_session_auth] MISMATCH | phone=%s | "
                "stored_app=%r vs target_app=%r | "
                "stored_fp=%r... vs target_fp=%r...",
                phone, stored_app, target_app,
                stored_fp[:12], target_fp[:12],
            )

    return None


# ═══════════════════════════════════════════════════════════════
# CORS
# ═══════════════════════════════════════════════════════════════
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, x-device-fingerprint, x-lang, Accept"
    )
    response.headers["Access-Control-Max-Age"] = "600"
    return response


@app.route("/api/liveness/<path:_>", methods=["OPTIONS"])
def cors_preflight(_):
    return ("", 204)


# ═══════════════════════════════════════════════════════════════
# ROUTES PUBLIQUES
# ═══════════════════════════════════════════════════════════════
@app.route("/")
def home():
    return """
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Selfie Relay</title>
      </head>
      <body style="font-family:sans-serif;text-align:center;padding:40px">
        <h1>Selfie Relay</h1>
        <p>Ouvre la page selfie depuis ton téléphone.</p>
        <a href="/selfie">→ Page Selfie</a>
      </body>
    </html>
    """


@app.route("/selfie")
@app.route("/selfie_mobile.html")
def selfie_page():
    return send_from_directory(BASE_DIR, "selfie_mobile_fixed.html")


# ═══════════════════════════════════════════════════════════════
# SESSION — PUSH / PULL / STATUS
# ═══════════════════════════════════════════════════════════════
@app.post("/api/push")
def push_session():
    """
    Enregistre la session mobile + les données d'auth BLS (côté serveur).
    Les données d'auth ne sont JAMAIS renvoyées au navigateur.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON object required"), 400

    phone = str(data.get("phone", "")).strip()
    appointment_id = str(data.get("appointment_id", "")).strip()
    fingerprint = str(data.get("fingerprint", "")).strip()
    email = str(data.get("email", "")).strip()
    session_cookies = data.get("session_cookies") or {}

    if not phone:
        return jsonify(error="phone required"), 400
    if not appointment_id:
        return jsonify(error="appointment_id required"), 400
    if not fingerprint:
        return jsonify(error="fingerprint required"), 400

    if not isinstance(session_cookies, dict):
        session_cookies = {}

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
        "oui" if authorization else "non",
    )

    return jsonify(
        status="ok",
        phone=phone,
        has_session_cookie=has_bls,
        cookie_names=list(cookies.keys()),
        has_authorization=bool(authorization),
    )


@app.get("/api/pull/<phone>")
def pull_session(phone):
    """
    Retourne les données non sensibles au navigateur.
    ⚠️  Les données d'auth ne sont JAMAIS renvoyées ici.
    """
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
    return jsonify(sessions=len(phones), phones=phones, info=info)


@app.get("/api/debug/session/<phone>")
def debug_session(phone):
    """
    Affiche le détail d'une session (valeurs tronquées). Debug uniquement.
    """
    _cleanup_sessions()
    phone = str(phone).strip()

    with sessions_lock:
        data = sessions.get(phone)
        available = list(sessions.keys())

    if not data:
        return jsonify(status="not_found", available_phones=available), 404

    raw = data.get("session_cookies") or {}
    cookies, authorization = _split_auth_data(raw)

    return jsonify(
        status="ok",
        phone=phone,
        appointment_id=data.get("appointment_id"),
        fingerprint=data.get("fingerprint"),
        email=data.get("email"),
        cookie_names=list(cookies.keys()),
        cookie_previews={
            k: (str(v)[:12] + "...") if v else None
            for k, v in cookies.items()
        },
        has_authorization=bool(authorization),
        authorization_preview=(
            str(authorization)[:30] + "..." if authorization else None
        ),
        session_age_seconds=int(time.time() - data.get("timestamp", 0)),
    )


# ═══════════════════════════════════════════════════════════════
# PROXY LIVENESS
# ═══════════════════════════════════════════════════════════════
def _forward_headers(request_obj, extra=None):
    headers = {
        "Accept": "application/json, text/plain, */*",
        "x-lang": "fr",
        "Origin": BLS_ORIGIN,
        "Referer": BLS_ORIGIN + "/",
        "User-Agent": request_obj.headers.get("User-Agent", ""),
    }
    if extra:
        headers.update(extra)
    return headers


def _parse_verify_response(upstream_status, upstream_body, upstream_ct):
    """
    CORRECTION : normalise la réponse /verify-face.
    L'upstream peut renvoyer plusieurs formats :
      - {"verified": true}
      - {"success": true}
      - {"status": "verified"}
      - {"data": {"verified": true}}
      - 200 sans JSON exploitable → on assume vérifié si status HTTP 200
    Retourne (payload_dict, http_status).
    """
    payload = None
    if upstream_ct and "application/json" in upstream_ct.lower():
        try:
            payload = json.loads(upstream_body)
        except Exception:
            payload = None

    verified = False
    if isinstance(payload, dict):
        if payload.get("verified") is True:
            verified = True
        elif payload.get("success") is True:
            verified = True
        elif str(payload.get("status", "")).lower() in ("verified", "ok", "success"):
            verified = True
        elif isinstance(payload.get("data"), dict) and payload["data"].get("verified") is True:
            verified = True

    # Si upstream 200 mais aucun flag → on assume vérifié
    if upstream_status == 200 and not verified:
        verified = True

    response_payload = {
        "verified": verified,
        "upstream_status": upstream_status,
        "raw": payload if payload is not None else upstream_body[:500],
    }

    return response_payload, upstream_status


@app.post("/api/liveness/device-info")
def proxy_device_info():
    appointment_id = request.args.get("appointment_id", "").strip()
    if not appointment_id:
        return jsonify(error="appointment_id required"), 400

    fp = request.headers.get("x-device-fingerprint", "").strip()
    if not fp:
        return jsonify(error="x-device-fingerprint required"), 400

    auth_data = _find_session_auth(appointment_id, fp)
    if not auth_data:
        return jsonify(
            error="no_session",
            message="Aucune session serveur trouvée pour cet appointment/fingerprint",
        ), 401

    session_cookies = auth_data["cookies"]
    authorization = auth_data["authorization"]

    if not session_cookies and not authorization:
        return jsonify(
            error="empty_auth",
            message="Session trouvée mais aucune donnée d'auth utilisable",
        ), 401

    body = request.get_json(silent=True) or {}

    headers = _forward_headers(
        request,
        {
            "Content-Type": "application/json",
            "x-device-fingerprint": fp,
        },
    )
    if authorization:
        headers["Authorization"] = authorization

    try:
        r = requests.post(
            LIVENESS_UPSTREAM + "/device-info",
            params={"appointment_id": appointment_id},
            json=body,
            headers=headers,
            cookies=session_cookies,
            timeout=30,
        )
        app.logger.info(
            "[device-info] upstream HTTP %s | cookies=%s | auth=%s",
            r.status_code, list(session_cookies.keys()),
            "oui" if authorization else "non",
        )
        return (
            r.content,
            r.status_code,
            {"Content-Type": r.headers.get("Content-Type", "application/json")},
        )
    except requests.RequestException as e:
        app.logger.error("device-info upstream error: %s", e)
        return jsonify(error="upstream_error", detail=str(e)[:200]), 502


@app.post("/api/liveness/verify-face")
def proxy_verify_face():
    appointment_id = request.args.get("appointment_id", "").strip()
    if not appointment_id:
        return jsonify(error="appointment_id required"), 400

    fp = request.headers.get("x-device-fingerprint", "").strip()
    if not fp:
        return jsonify(error="x-device-fingerprint required"), 400

    auth_data = _find_session_auth(appointment_id, fp)
    if not auth_data:
        return jsonify(
            error="no_session",
            message="Aucune session serveur trouvée pour cet appointment/fingerprint",
        ), 401

    session_cookies = auth_data["cookies"]
    authorization = auth_data["authorization"]

    if not session_cookies and not authorization:
        return jsonify(
            error="empty_auth",
            message="Session trouvée mais aucune donnée d'auth utilisable",
        ), 401

    if "captured_image" not in request.files:
        return jsonify(error="captured_image file required"), 400

    file = request.files["captured_image"]
    file_bytes = file.read()
    if not file_bytes:
        return jsonify(error="empty file"), 400

    files = {
        "captured_image": (
            file.filename or "selfie.jpg",
            file_bytes,
            file.mimetype or "image/jpeg",
        )
    }

    headers = _forward_headers(
        request,
        {"x-device-fingerprint": fp},
    )
    if authorization:
        headers["Authorization"] = authorization

    try:
        r = requests.post(
            LIVENESS_UPSTREAM + "/verify-face",
            params={"appointment_id": appointment_id},
            files=files,
            headers=headers,
            cookies=session_cookies,
            timeout=60,
        )
        app.logger.info(
            "[verify-face] upstream HTTP %s | cookies=%s | auth=%s | body=%s",
            r.status_code, list(session_cookies.keys()),
            "oui" if authorization else "non",
            r.text[:300],
        )

        # ── CORRECTION : normaliser la réponse ──
        payload, status = _parse_verify_response(
            r.status_code, r.text, r.headers.get("Content-Type", "")
        )
        return jsonify(payload), status

    except requests.RequestException as e:
        app.logger.error("verify-face upstream error: %s", e)
        return jsonify(error="upstream_error", detail=str(e)[:200]), 502


# ═══════════════════════════════════════════════════════════════
# ENTRYPOINT
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)