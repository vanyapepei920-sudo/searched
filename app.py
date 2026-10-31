# -*- coding: utf-8 -*-
"""
SearchGPT — собственный поисковик на базе Google Custom Search API.

Возможности:
  * Поиск через Google CSE (GOOGLE_API_KEY + GOOGLE_CX_ID)
  * Обязательный вход через Google-аккаунт (OAuth 2.0) для веб-интерфейса
    — реализован на чистом requests, БЕЗ authlib (Termux-friendly)
  * Публичный REST API (/api/v1/search) с ключами доступа (403 без ключа)
  * AI-ответ поверх выдачи через Pollinations.AI (бесплатно, без ключа)
  * Страница «Настройки» со всеми опциями интерфейса
  * Тёмная / светлая тема, интерфейс в стиле Google

Работает на Termux:  pkg install python && pip install -r requirements.txt && python app.py
"""

import json
import os
import secrets
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    Response,
    session,
    url_for,
)

load_dotenv()

# ----------------------------------------------------------------------------
# Конфигурация из .env
# ----------------------------------------------------------------------------
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "").strip()
GOOGLE_CX_ID = os.getenv("GOOGLE_CX_ID", "").strip()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

SECRET_KEY = os.getenv("SECRET_KEY", "").strip() or secrets.token_hex(32)

# ИИ-ответ генерируется через Pollinations.AI — бесплатный OpenAI-совместимый
# API (https://github.com/pollinations/pollinations), ключ не требуется.
POLLINATIONS_URL = os.getenv(
    "POLLINATIONS_URL", "https://text.pollinations.ai"
).strip().rstrip("/")
POLLINATIONS_MODEL = os.getenv("POLLINATIONS_MODEL", "openai").strip()
AI_ENABLED_DEFAULT = os.getenv("AI_ENABLED", "1").strip().lower() not in (
    "0", "false", "off", "no",
)

PORT = int(os.getenv("PORT", "4000"))

SEARCH_API_KEYS = {
    k.strip() for k in os.getenv("SEARCH_API_KEYS", "").split(",") if k.strip()
}

CSE_URL = "https://www.googleapis.com/customsearch/v1"
NUM_RESULTS = 10

# ----------------------------------------------------------------------------
# Настройки пользователя (страница /settings): сохраняются в cookie браузера,
# поэтому работают без БД и переживают перезагрузку сервера.
# ----------------------------------------------------------------------------
SETTINGS_DEFAULTS = {
    "theme": "dark",                    # dark | light
    "results_per_page": 10,             # 5 | 10 | 20
    "safe_search": True,                # фильтрация нежелательного контента
    "ai_enabled": AI_ENABLED_DEFAULT,   # показывать блок «Ответ ИИ»
    "ai_model": POLLINATIONS_MODEL,     # модель Pollinations
    "language": "ru",                   # ru | en | ua | es | de
    "new_tab": True,                    # открывать результаты в новой вкладке
    "instant_answers": True,            # мгновенные ответы ИИ прямо на главной
    "sound": False,                     # звук при ответе ИИ
    "autosuggest": True,                # подсказки в строке поиска
}

VALID_MODELS = ["openai", "mistral", "llama", "deepseek", "searchgpt"]
VALID_LANGS = {"ru": "Русский", "en": "English", "ua": "Українська", "es": "Español", "de": "Deutsch"}
VALID_RPP = [5, 10, 20]

COOKIE_NAME = "sgpt_settings"
COOKIE_MAX_AGE = 60 * 60 * 24 * 365


def get_settings() -> dict:
    """Читает настройки из cookie и дополняет значениями по умолчанию."""
    s = dict(SETTINGS_DEFAULTS)
    raw = request.cookies.get(COOKIE_NAME)
    if raw:
        try:
            loaded = json.loads(raw)
        except Exception:
            # Браузер мог прислать URL-encoded значение (мы его так и ставим)
            try:
                from urllib.parse import unquote
                loaded = json.loads(unquote(raw))
            except Exception:
                loaded = None
        if isinstance(loaded, dict):
            s.update(loaded)
    # Валидация
    if s["theme"] not in ("dark", "light"):
        s["theme"] = "dark"
    try:
        s["results_per_page"] = int(s["results_per_page"])
    except Exception:
        s["results_per_page"] = 10
    if s["results_per_page"] not in VALID_RPP:
        s["results_per_page"] = 10
    for b in ("safe_search", "ai_enabled", "new_tab", "instant_answers", "sound", "autosuggest"):
        s[b] = bool(s[b])
    if s["language"] not in VALID_LANGS:
        s["language"] = "ru"
    if s["ai_model"] not in VALID_MODELS:
        s["ai_model"] = POLLINATIONS_MODEL
    return s


def settings_response(resp: Response, settings: dict) -> Response:
    resp.set_cookie(
        COOKIE_NAME,
        json.dumps(settings),
        max_age=COOKIE_MAX_AGE,
        httponly=False,  # читаем из JS для мгновенной смены темы
        samesite="Lax",
    )
    return resp


# ----------------------------------------------------------------------------
# Приложение
# ----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["PREFERRED_URL_SCHEME"] = "http"


@app.context_processor
def inject_globals():
    """Достаёт настройки текущего пользователя во всех шаблонах."""
    try:
        st = get_settings()
    except Exception:
        st = dict(SETTINGS_DEFAULTS)
    return {
        "st": st,
        "lang_name": VALID_LANGS.get(st["language"], "Русский"),
    }


# ----------------------------------------------------------------------------
# Google OAuth 2.0 на чистом requests (без authlib — никаких нативных
# зависимостей, все пакеты ставятся чистым pip, работает на Termux)
# ----------------------------------------------------------------------------
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


def build_google_auth_url(state: str) -> str:
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": url_for("callback", _external=True),
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def google_exchange_code(code: str):
    """Обменивает authorization code на access token."""
    try:
        r = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": url_for("callback", _external=True),
            },
            timeout=15,
        )
        if r.status_code != 200:
            return None
        return r.json()
    except requests.RequestException:
        return None


def google_userinfo(access_token: str):
    try:
        r = requests.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
        if r.status_code != 200:
            return None
        return r.json()
    except requests.RequestException:
        return None


# ----------------------------------------------------------------------------
# Вспомогательные функции поиска / ИИ
# ----------------------------------------------------------------------------
def google_search(query: str, page: int = 1, num: int = NUM_RESULTS, safe: bool = True):
    """Запрос к Google Custom Search API. Возвращает dict или {'error': ...}."""
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
                **({"safe": "active"} if safe else {}),
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
            pagemap = it.get("pagemap", {}) or {}
            thumb = None
            if pagemap.get("cse_thumbnail"):
                thumb = pagemap["cse_thumbnail"][0].get("src")
            items.append(
                {
                    "title": it.get("title", ""),
                    "link": it.get("link", ""),
                    "snippet": it.get("snippet", ""),
                    "displayLink": it.get("displayLink", ""),
                    "thumbnail": thumb,
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


def ai_answer(query: str, results: list, model=None):
    """Генерирует краткий ИИ-ответ через Pollinations.AI (бесплатно, без ключа).

    Модель получает фрагменты результатов поиска и отвечает на их основе.
    """
    if not AI_ENABLED_DEFAULT:
        return None
    context_lines = []
    for i, it in enumerate(results[:8], 1):
        context_lines.append(f"[{i}] {it['title']} — {it['link']}\n{it['snippet']}")
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
                "model": model or POLLINATIONS_MODEL,
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
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    return redirect(build_google_auth_url(state))


@app.route("/auth/callback")
def callback():
    if request.args.get("state") != session.get("oauth_state"):
        return redirect(url_for("login"))
    code = request.args.get("code", "")
    if not code:
        return redirect(url_for("login"))
    tokens = google_exchange_code(code)
    if not tokens or "access_token" not in tokens:
        return redirect(url_for("login"))
    userinfo = google_userinfo(tokens["access_token"]) or {}
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
    return render_template(
        "index.html",
        user=session.get("user"),
        query="",
        results=None,
        error=None,
        ai=None,
        page=1,
    )


@app.route("/search")
@app.route("/search?<path:query>")  # Google-стиль: /search?=Запрос и /search?Запрос
def search_page(query=None):
    st = get_settings()
    # приоритет: ?search=Запрос > путь после «?» (/search?Запрос) > обычный ?q=
    query = (
        request.args.get("search")
        or query
        or request.args.get("q", "")
    ).strip()
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1

    results, error, ai = None, None, None
    if query:
        data = google_search(query, page=page, num=st["results_per_page"], safe=st["safe_search"])
        if "error" in data:
            error = data["error"]
        else:
            results = data
            if st["ai_enabled"]:
                ai = ai_answer(query, results["items"], model=st["ai_model"])

    return render_template(
        "results.html",
        user=session.get("user"),
        query=query,
        results=results,
        error=error,
        ai=ai,
        page=page,
        ai_enabled=st["ai_enabled"],
        results_per_page_num=st["results_per_page"],
        on_results=True,
    )


@app.route("/lucky")
@app.route("/lucky?<path:query>")  # Google-стиль: /lucky?=Запрос
def lucky(query=None):
    """«Мне повезёт» — редирект на первый результат поиска."""
    query = (request.args.get("search") or query or request.args.get("q", "")).strip()
    if not query:
        return redirect(url_for("index"))
    st = get_settings()
    data = google_search(query, num=st["results_per_page"], safe=st["safe_search"])
    items = data.get("items", [])
    if items:
        return redirect(items[0]["link"])
    return redirect(url_for("search_page", q=query))


# ----------------------------------------------------------------------------
# Настройки
# ----------------------------------------------------------------------------
@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    st = get_settings()
    saved = False
    if request.method == "POST":
        new = dict(st)
        new["theme"] = request.form.get("theme", st["theme"])
        new["language"] = request.form.get("language", st["language"])
        new["ai_model"] = request.form.get("ai_model", st["ai_model"])
        try:
            new["results_per_page"] = int(
                request.form.get("results_per_page", st["results_per_page"])
            )
        except Exception:
            pass
        for b in ("safe_search", "ai_enabled", "new_tab", "instant_answers", "sound", "autosuggest"):
            new[b] = request.form.get(b) == "on"
        resp = redirect(url_for("settings_page", saved=1))
        return settings_response(resp, new)

    if request.args.get("saved") == "1":
        saved = True

    return render_template(
        "settings.html",
        user=session.get("user"),
        st=st,
        saved=saved,
        valid_models=VALID_MODELS,
        valid_langs=VALID_LANGS,
        valid_rpp=VALID_RPP,
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
        return jsonify({
            "answer": None,
            "sources": sources,
            "detail": "ИИ-ответ отключён (AI_ENABLED=0) или Pollinations недоступен",
        }), 200
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
                 "owned_by": "self", "description": "Поиск + ИИ-ответ (Pollinations)"},
            ],
        }
    )


@app.route("/api/v1/instant")
def api_instant():
    """Лёгкий эндпоинт для мгновенного ответа ИИ на главной (для залогиненных)."""
    if not session.get("user") or not get_settings()["instant_answers"]:
        return jsonify({"answer": None}), 200
    query = request.args.get("q", "").strip()
    if len(query) < 4:
        return jsonify({"answer": None}), 200
    data = google_search(query, num=5)
    items = data.get("items", []) if "error" not in data else []
    st = get_settings()
    answer = ai_answer(query, items, model=st["ai_model"]) if st["ai_enabled"] else None
    return jsonify({"answer": answer})


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "cse_configured": bool(GOOGLE_API_KEY and GOOGLE_CX_ID),
            "oauth_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
            "ai_provider": "pollinations.ai",
            "ai_configured": AI_ENABLED_DEFAULT,
            "api_keys_loaded": len(SEARCH_API_KEYS),
        }
    )


if __name__ == "__main__":
    print(f"🔎 SearchGPT запущен: http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
