# -*- coding: utf-8 -*-
"""
SearchGPT — собственный поисковик на базе Google Custom Search API.

Возможности:
  * Поиск через Google CSE (GOOGLE_API_KEY + GOOGLE_CX_ID)
  * Обязательный вход через Google-аккаунт (OAuth 2.0) для веб-интерфейса
  * Публичный REST API (/api/v1/search) с ключами доступа (403 без ключа)
  * AI-ответ поверх выдачи через Pollinations.AI (бесплатно, без ключа)
  * Тёмная / светлая тема, интерфейс в стиле Google

Работает на Termux:  pip install -r requirements.txt && python app.py
"""

import json
import os
import secrets
from urllib.parse import quote_plus

import requests
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

load_dotenv()

# ----------------------------------------------------------------------------
# Конфигурация
# ----------------------------------------------------------------------------
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "").strip()
GOOGLE_CX_ID = os.getenv("GOOGLE_CX_ID", "").strip()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

SECRET_KEY = os.getenv("SECRET_KEY", "").strip() or secrets.token_hex(32)

# ИИ-ответ генерируется через Pollinations.AI — бесплатный OpenAI-совместимый
# API (https://github.com/pollinations/pollinations), ключ не требуется.
POLLINATIONS_URL = os.getenv(
    "POLLINATIONS_URL", "https://text.pollinations.ai/openai"
).strip().rstrip("/")
POLLINATIONS_MODEL = os.getenv("POLLINATIONS_MODEL", "openai").strip()
AI_ENABLED = os.getenv("AI_ENABLED", "1").strip().lower() not in ("0", "false", "off", "no")

PORT = int(os.getenv("PORT", "4000"))

SEARCH_API_KEYS = {
    k.strip() for k in os.getenv("SEARCH_API_KEYS", "").split(",") if k.strip()
}

CSE_URL = "https://www.googleapis.com/customsearch/v1"
NUM_RESULTS = 10

# ----------------------------------------------------------------------------
# Приложение
# ----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["PREFERRED_URL_SCHEME"] = "http"

oauth = OAuth(app)
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


# ----------------------------------------------------------------------------
# Вспомогательные функции
# ----------------------------------------------------------------------------
def google_search(query: str, page: int = 1, num: int = NUM_RESULTS):
    """Запрос к Google Custom Search API. Возвращает dict или None."""
    if not (GOOGLE_API_KEY and GOOGLE_CX_ID):
        return {"error": "GOOGLE_API_KEY / GOOGLE_CX_ID не настроены в .env"}
    try:
        r = requests.get(
            CSE_URL,
            params={
                "key": GOOGLE_API_KEY,
                "cx": GOOGLE_CX_ID,
                "q": query,
                "num": min(num, 10),
                "start": max(page, 1) * num - num + 1,
            },
            timeout=15,
        )
        if r.status_code != 200:
            try:
                msg = r.json().get("error", {}).get("message", r.text)
            except Exception:
                msg = r.text
            return {"error": f"Google API: {msg}"}
        data = r.json()
        items = []
        for it in data.get("items", []):
            items.append(
                {
                    "title": it.get("title", ""),
                    "link": it.get("link", ""),
                    "snippet": it.get("snippet", ""),
                    "displayLink": it.get("displayLink", ""),
                    "thumbnail": (it.get("pagemap", {}) or {}).get("cse_thumbnail", [{}])[0].get("src")
                    if it.get("pagemap") and it.get("pagemap", {}).get("cse_thumbnail")
                    else None,
                }
            )
        qi = data.get("searchInformation", {})
        total = int(qi.get("totalResults", "0") or 0)
        return {
            "items": items,
            "total": total,
            "searchTime": qi.get("searchTime"),
            "hasMore": page * num < total,
        }
    except requests.RequestException as e:
        return {"error": f"Сеть недоступна: {e}"}


def ai_answer(query: str, results: list) -> str | None:
    """Генерирует краткий ИИ-ответ через Pollinations.AI (бесплатно, без ключа).

    Модель получает фрагменты результатов поиска и отвечает на их основе.
    Pollinations предоставляет OpenAI-совместимый эндпоинт /v1/chat/completions.
    """
    if not AI_ENABLED:
        return None
    context_lines = []
    for i, it in enumerate(results[:8], 1):
        context_lines.append(
            f"[{i}] {it['title']} — {it['link']}\n{it['snippet']}"
        )
    context = "\n\n".join(context_lines) or "(нет результатов)"
    messages = [
        {
            "role": "system",
            "content": (
                "Ты — ИИ-ассистент собственного поисковика. Дай краткий, точный и "
                "полезный ответ на запрос пользователя, опираясь на предоставленные "
                "фрагменты из результатов поиска. Если данных недостаточно, отвечай "
                "на основе общих знаний и честно предупреди об этом. Не выдумывай "
                "ссылки. Отвечай на языке запроса. Формат: обычный текст без markdown."
            ),
        },
        {
            "role": "user",
            "content": f"Запрос: {query}\n\nРезультаты поиска:\n{context}",
        },
    ]
    try:
        r = requests.post(
            f"{POLLINATIONS_URL}/v1/chat/completions",
            headers={"Content-Type": "application/json"},
            json={
                "model": POLLINATIONS_MODEL,
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 700,
            },
            timeout=60,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        content = data["choices"][0]["message"]["content"].strip()
        return content or None
    except Exception:
        return None


def check_api_key() -> bool:
    """Проверяет ключ программного доступа (Bearer / ?key= / X-API-Key)."""
    if not SEARCH_API_KEYS:
        return False
    key = ""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        key = auth[7:].strip()
    key = key or request.headers.get("X-API-Key", "").strip()
    key = key or request.args.get("key", "").strip()
    return key in SEARCH_API_KEYS


# ----------------------------------------------------------------------------
# Защита веб-интерфейса: обязателен вход через Google
# ----------------------------------------------------------------------------
@app.before_request
def require_google_login():
    path = request.path
    public = (
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
        "/api/",              # REST API защищён отдельными ключами
        "/static/",
        "/favicon.ico",
        "/health",
    )
    if any(path.startswith(p) for p in public):
        return None
    if not session.get("user"):
        return redirect(url_for("login"))
    return None


# ----------------------------------------------------------------------------
# Маршруты авторизации
# ----------------------------------------------------------------------------
@app.route("/auth/login")
def login():
    if not GOOGLE_CLIENT_ID:
        return render_template(
            "error.html",
            title="Не настроен вход через Google",
            detail=(
                "В файле .env не заполнены GOOGLE_CLIENT_ID и GOOGLE_CLIENT_SECRET.<br>"
                "Создайте OAuth 2.0 клиента на "
                "<a href='https://console.cloud.google.com/apis/credentials'>"
                "console.cloud.google.com/apis/credentials</a> "
                "и укажите Redirect URI: <code>http://localhost:4000/auth/callback</code>."
            ),
        )
    redirect_uri = url_for("callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def callback():
    try:
        token = oauth.google.authorize_access_token()
        userinfo = token.get("userinfo") or oauth.google.get("userinfo").json()
    except Exception:
        return redirect(url_for("login"))
    session["user"] = {
        "name": userinfo.get("name", "Пользователь"),
        "email": userinfo.get("email", ""),
        "picture": userinfo.get("picture", ""),
    }
    return redirect(url_for("index"))


@app.route("/auth/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ----------------------------------------------------------------------------
# Страницы поисковика
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"),
                           query="", results=None, error=None, ai=None, page=1)


@app.route("/search")
def search_page():
    query = request.args.get("q", "").strip()
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1

    results, error, ai = None, None, None
    if query:
        data = google_search(query, page=page)
        if "error" in data:
            error = data["error"]
        else:
            results = data
            ai = ai_answer(query, results["items"])

    return render_template(
        "results.html",
        user=session.get("user"),
        query=query,
        results=results,
        error=error,
        ai=ai,
        page=page,
        ai_enabled=AI_ENABLED,
    )


# ----------------------------------------------------------------------------
# Публичный REST API (для других проектов). Без ключа — 403.
# ----------------------------------------------------------------------------
@app.route("/api/v1/search", methods=["GET", "POST"])
def api_search():
    if not check_api_key():
        return (
            jsonify(
                {
                    "error": {
                        "code": 403,
                        "message": "Доступ запрещён. Передайте API-ключ: "
                                   "заголовок 'Authorization: Bearer <ключ>' "
                                   "или параметр '?key=<ключ>'.",
                    }
                }
            ),
            403,
        )

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        query = (payload.get("query") or payload.get("q") or "").strip()
        page = int(payload.get("page", 1) or 1)
        want_ai = bool(payload.get("ai", False))
    else:
        query = request.args.get("q", "").strip()
        page = int(request.args.get("page", 1) or 1)
        want_ai = request.args.get("ai", "0") in ("1", "true", "yes")

    if not query:
        return jsonify({"error": {"code": 400, "message": "Параметр 'q' обязателен"}}), 400

    data = google_search(query, page=max(page, 1))
    if "error" in data:
        return jsonify(data), 502

    resp = {"query": query, "page": page, **data}
    if want_ai:
        resp["ai_answer"] = ai_answer(query, data["items"])
    return jsonify(resp)


@app.route("/api/v1/answer", methods=["GET", "POST"])
def api_answer():
    """Только ИИ-ответ (берёт контекст из поиска сам)."""
    if not check_api_key():
        return jsonify({"error": {"code": 403, "message": "Требуется API-ключ"}}), 403
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        query = (payload.get("query") or payload.get("q") or "").strip()
    else:
        query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"error": {"code": 400, "message": "Параметр 'q' обязателен"}}), 400
    data = google_search(query)
    items = data.get("items", []) if "error" not in data else []
    answer = ai_answer(query, items)
    sources = [{"title": i["title"], "url": i["link"]} for i in items[:8]]
    if answer is None:
        return jsonify({"answer": None, "sources": sources,
                        "detail": "ИИ-ответ отключён (AI_ENABLED=0) или Pollinations недоступен"}), 200
    return jsonify({"answer": answer, "sources": sources})


@app.route("/api/v1/models")
def api_models():
    """Как у OpenAI: список доступных 'моделей' нашего поисковика."""
    if not check_api_key():
        return jsonify({"error": {"code": 403, "message": "Требуется API-ключ"}}), 403
    return jsonify(
        {
            "object": "list",
            "data": [
                {"id": "search-google", "object": "model",
                 "owned_by": "self", "description": "Поиск через Google CSE"},
                {"id": "search-ai", "object": "model",
                 "owned_by": "self", "description": "Поиск + ИИ-ответ"},
            ],
        }
    )


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "cse_configured": bool(GOOGLE_API_KEY and GOOGLE_CX_ID),
            "oauth_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
            "ai_provider": "pollinations.ai",
            "ai_configured": AI_ENABLED,
            "api_keys_loaded": len(SEARCH_API_KEYS),
        }
    )


if __name__ == "__main__":
    print(f"🔎 SearchGPT запущен: http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
