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

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from urllib.parse import urlencode, urlparse, quote

import requests
from dotenv import load_dotenv
from markupsafe import Markup
from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    Response,
    session,
    url_for,
)
try:  # Flask >= 2.0 отдаёт escape из markupsafe, но на всякий случай — fallback
    from flask import escape
except ImportError:
    from markupsafe import escape

load_dotenv()

# ----------------------------------------------------------------------------
# Конфигурация из .env
# ----------------------------------------------------------------------------
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "").strip()
GOOGLE_CX_ID = os.getenv("GOOGLE_CX_ID", "").strip()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

SECRET_KEY = os.getenv("SECRET_KEY", "").strip() or secrets.token_hex(32)

# Публичный адрес приложения для OAuth redirect_uri.
# Нужен, когда сайт открыт не напрямую с localhost:4000 (например через
# ngrok / cloudflared / свой домен или по IP локальной сети): Google сверяет
# redirect_uri строго посимвольно и выдаёт "Error 400: redirect_uri_mismatch",
# если в консоли Cloud указан другой адрес.
#   PUBLIC_BASE_URL=https://abc123.ngrok-free.app
# Если оставить пустым — адрес вычисляется автоматически из запроса.
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")


def public_origin() -> str:
    """Публичный адрес сайта (scheme://host[:port]) — источник redirect_uri."""
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    # Прокси (cloudpub/ngrok/cloudflared): смотрим служебные заголовки.
    for h in ("X-Forwarded-Prefix", ):
        pass  # префиксы не поддерживаем — приложение живёт в корне домена
    fwd_host = request.headers.get("X-Forwarded-Host")
    if fwd_host:
        scheme = request.headers.get("X-Forwarded-Proto", "https").split(",")[0].strip()
        host = fwd_host.split(",")[0].strip()
        return f"{scheme}://{host}"
    host = request.headers.get("Host") or ""
    if host:
        # Если прокси сообщил, что снаружи это https — не отдаём http-адрес
        xf_proto = request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip()
        scheme = "https" if (xf_proto == "https" or request.is_secure) else "http"
        return f"{scheme}://{host}"
    return request.url_root.rstrip("/")


def oauth_redirect_uri() -> str:
    """redirect_uri, который реально уходит в Google (и должен быть в консоли).

    ВАЖНО: Google сверяет этот адрес со списком в Cloud Console строго
    посимвольно (схема, хост, порт, слэш). Добавляйте в консоль ровно то,
    что показывает страница /auth/redirect-uri при текущем способе входа.
    """
    return public_origin() + "/auth/callback"

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
CSE_ENABLE_LINK = ("https://console.cloud.google.com/apis/library/customsearch.googleapis.com"
                   "?project=_")
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
    "search_engine": "auto",            # auto | google | duckduckgo
    "cse_key": "",                      # свой GOOGLE_API_KEY (если пуст — из .env)
    "cse_id": "",                       # свой GOOGLE_CX_ID (если пуст — из .env)
    # Диагностика Google CSE: статус API и поисковой системы (см. /settings/diag)
    "cse_api_status": "",               # ok | error:<msg> | "" (не проверялось)
    "cse_api_checked_at": 0,            # unix-time последней проверки
    "cse_sys_ok": None,                 # None|True|False — жив ли CX (кнопка «Проверить»)
    "cse_sys_checked_at": 0,
}

# Кэш диагностики статуса Custom Search JSON API для проекта ключа
# (чтобы не дёргать Cloud Billing API на каждом запросе). {key_prefix: (ts, status)}
CSE_DIAG_CACHE = {}
CSE_DIAG_TTL = 600  # 10 минут


def _short_err(e) -> str:
    """Короткое текстовое описание ошибки requests/HTTP."""
    try:
        resp = getattr(e, "response", None)
        if resp is not None:
            try:
                msg = resp.json().get("error", {}).get("message", "")
            except Exception:
                msg = ""
            return f"HTTP {resp.status_code}" + (f": {msg[:200]}" if msg else "")
    except Exception:
        pass
    return str(e)[:200]


def cse_api_diag(api_key: str):
    """Диагностика по Cloud Billing API: список проектов с включённым
    Custom Search JSON API для данного ключа. Возвращает (status, текст),
    где status: 'ok' | 'not_enabled' | 'no_projects' | 'invalid_key' | 'net_error'.

    Это точный ответ на ошибку «This project does not have the access to
    Custom Search JSON API»: она означает, что проект, которому принадлежит
    КЛЮЧ, не имеет включённого API (даже если вы включили его в другом проекте).
    """
    if not api_key:
        return ("no_key", "GOOGLE_API_KEY не задан")
    ck = api_key[:8]
    hit = CSE_DIAG_CACHE.get(ck)
    now = time.time()
    if hit and now - hit[0] < CSE_DIAG_TTL:
        return hit[1]
    result = None
    try:
        r = requests.get(
            "https://cloudbilling.googleapis.com/v1/services",
            params={"key": api_key, "pageSize": 300},
            timeout=15,
        )
        if r.status_code == 400 or r.status_code == 403:
            msg = ""
            try:
                msg = r.json().get("error", {}).get("message", "").lower()
            except Exception:
                pass
            if "api key" in msg and ("not valid" in msg or "invalid" in msg):
                result = ("invalid_key", "API-ключ недействителен (проверьте значение)")
            else:
                result = ("no_projects", "Не удалось получить список проектов (403): " + msg[:150])
        elif r.status_code != 200:
            result = ("no_projects", f"Cloud Billing API: HTTP {r.status_code}")
        else:
            found = []
            for s in r.json().get("billingServices", []):
                if s.get("displayName") == "Custom Search API" or \
                        s.get("name", "").endswith("/customsearch"):
                    found.append(s.get("serviceId", "customsearch.googleapis.com"))
            if found:
                result = ("ok", "Custom Search JSON API включён в проекте ключа")
            else:
                result = ("not_enabled",
                          "В проекте этого API-ключа Custom Search JSON API НЕ включён")
    except requests.RequestException as e:
        result = ("net_error", "Сеть недоступна: " + _short_err(e))
    CSE_DIAG_CACHE[ck] = (now, result)
    return result


def check_cx_alive(api_key: str, cx_id: str):
    """Живой мини-тест CX: один запрос к CSE с num=1. Возвращает (ok, сообщение)."""
    if not api_key or not cx_id:
        return (False, "Нужны и ключ, и CX")
    try:
        r = requests.get(CSE_URL, params={"key": api_key, "cx": cx_id,
                                          "q": "test", "num": 1}, timeout=15)
        if r.status_code == 200:
            n = len(r.json().get("items", []) or [])
            return (True, f"CX работает, тестовая выдача: {n} результат(ов)")
        try:
            msg = r.json().get("error", {}).get("message", r.text[:200])
        except Exception:
            msg = r.text[:200]
        return (False, f"Google вернул {r.status_code}: {msg}")
    except requests.RequestException as e:
        return (False, "Сеть: " + _short_err(e))

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
    if s["search_engine"] not in ("auto", "google", "duckduckgo"):
        s["search_engine"] = "auto"
    for k in ("cse_key", "cse_id"):
        if not isinstance(s.get(k), str):
            s[k] = ""
        s[k] = s[k].strip()
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

    def nl2br(text):
        """Экранирует текст и переводит переносы строк в <br> (безопасно)."""
        return Markup(escape(str(text)).replace("\n", "<br>\n"))

    return {
        "st": st,
        "lang_name": VALID_LANGS.get(st["language"], "Русский"),
        "nl2br": nl2br,
    }


# ----------------------------------------------------------------------------
# Пользователи: регистрация / вход (SQLite из стандартной библиотеки Python —
# никаких дополнительных пакетов, работает на Termux).
# Пароли хранятся как PBKDF2-хэш с индивидуальной солью, без openpyxl/bcrypt.
# ----------------------------------------------------------------------------
DB_PATH = os.getenv("DB_PATH", "users.db").strip() or "users.db"


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 email TEXT DEFAULT '',
                 pw_hash TEXT NOT NULL,
                 pw_salt TEXT NOT NULL,
                 provider TEXT DEFAULT 'local',
                 picture TEXT DEFAULT '',
                 created_at TEXT DEFAULT CURRENT_TIMESTAMP
               )"""
        )


init_db()

PBKDF2_ITERATIONS = 120_000


def hash_password(password: str, salt_hex: str | None = None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return digest.hex(), salt.hex()


def verify_password(password: str, pw_hash: str, salt_hex: str) -> bool:
    digest, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(digest, pw_hash)


USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{3,30}$")


def get_current_user():
    """Пользователь из Flask-сессии (локальный аккаунт или вход через Google)."""
    u = session.get("user")
    if not u:
        return None
    # Вход через Google: данные уже в сессии, дополнительно подтянем username
    if u.get("provider") == "google":
        name = u.get("g_name") or u.get("name") or "Пользователь"
        if u.get("id"):
            row = db().execute(
                "SELECT username FROM users WHERE id=?", (u["id"],)
            ).fetchone()
            if row:
                name = row["username"]
        return {
            "id": u.get("id"),
            "name": name,
            "email": u.get("email", ""),
            "picture": u.get("picture", ""),
            "provider": "google",
        }
    row = db().execute(
        "SELECT id, username, email, provider, picture FROM users WHERE id=?",
        (u.get("id"),),
    ).fetchone()
    if not row:
        session.pop("user", None)
        return None
    return {
        "id": row["id"],
        "name": row["username"],
        "email": row["email"] or "",
        "picture": row["picture"] or "",
        "provider": row["provider"],
    }


def is_signed_in() -> bool:
    return get_current_user() is not None


# ----------------------------------------------------------------------------
# Google OAuth 2.0 на чистом requests (без authlib — никаких нативных
# зависимостей, все пакеты ставятся чистым pip, работает на Termux)
# ----------------------------------------------------------------------------
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
# Публичный metadata OAuth-клиента (для диагностики redirect_uri_mismatch)
GOOGLE_CLIENT_METADATA_URL = "https://cloudresourcemanager.googleapis.com/v1/clientIds/"


# Кэш ответа Google Cloud Console по OAuth-клиенту (нужен только для
# диагностики ошибки redirect_uri_mismatch).
_CLIENT_DIAG_CACHE = {"ts": 0.0, "data": None}


def client_id_diagnostic() -> dict:
    """Достаёт из Google конфигурацию OAuth-клиента по его client_id.

    Публичный metadata-эндпоинт возвращает authorized_redirect_uris клиента —
    ровно тот список, с которым Google сверяет redirect_uri. Если запрос не
    удался (нет ключа/интернета), тихо возвращаем пустой словарь.
    """
    if not GOOGLE_CLIENT_ID:
        return {}
    now = time.time()
    if _CLIENT_DIAG_CACHE["data"] is not None and now - _CLIENT_DIAG_CACHE["ts"] < 60:
        return _CLIENT_DIAG_CACHE["data"]
    data: dict = {}
    try:
        r = requests.get(
            GOOGLE_CLIENT_METADATA_URL
            + quote(GOOGLE_CLIENT_ID, safe=""),
            timeout=8,
        )
        if r.status_code == 200:
            j = r.json()
            web = j.get("web") or {}
            uris = [u.rstrip("/") for u in web.get("authorizedRedirectUris", [])]
            data = {
                "redirect_uris": uris,
                "client_name": web.get("name", ""),
                "available": True,
            }
    except Exception:
        pass
    _CLIENT_DIAG_CACHE.update({"ts": now, "data": data})
    return data


def pick_redirect_uri() -> str:
    """Выбирает redirect_uri, который точно есть в настройках клиента.

    1) PUBLIC_BASE_URL задан вручную — используем его без вопросов;
    2) иначе пробуем адрес, вычисленный из текущего запроса;
    3) если он не совпадает со списком из консоли (когда список доступен),
       берём первое http(s)-совпадение по хосту — это лечит mismatch при
       доступе через прокси (https снаружи / http внутри).
    """
    candidate = oauth_redirect_uri()
    diag = client_id_diagnostic()
    allowed = diag.get("redirect_uris") or []
    if not allowed or candidate.rstrip("/") in allowed:
        return candidate
    # подбираем похожий адрес из списка консоли
    host = urlparse(candidate).netloc
    same_host = [u for u in allowed if urlparse(u).netloc == host]
    if same_host:
        return same_host[0]
    app.logger.warning(
        "redirect_uri %s отсутствует в консоли Google; доступны: %s",
        candidate, allowed,
    )
    return candidate


def build_google_auth_url(state: str, next_url: str = "/") -> str:
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": pick_redirect_uri(),
        "response_type": "code",
        # openid обязателен для обмена кода на токены с профилем Google
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


# ----------------------------------------------------------------------------
# OAuth state: серверный реестр состояний входа. Cookie-сессии может не
# дождаться через сторонние прокси (cloudpub/ngrok/cloudflared) — тогда
# callback отклонялся без причины. state живёт 10 минут и используется один раз.
# ----------------------------------------------------------------------------
OAUTH_STATES: dict = {}   # state -> {"next": str, "exp": float}


def _remember_state(state: str, next_url: str, redirect_uri: str) -> None:
    now = time.time()
    for k in [k for k, v in OAUTH_STATES.items() if v["exp"] < now]:
        OAUTH_STATES.pop(k, None)
    OAUTH_STATES[state] = {
        "next": safe_next(next_url),
        "uri": redirect_uri,
        "exp": now + 600,
    }


def _state_ok(state: str) -> bool:
    rec = OAUTH_STATES.get(state)
    return bool(rec and rec["exp"] > time.time())


def _state_data(state: str) -> dict:
    """Возвращает и удаляет запись состояния (одноразовое использование)."""
    rec = OAUTH_STATES.pop(state, None)
    if rec is None:
        # куки дожили — используем запасной вариант из сессии
        return {
            "next": safe_next(session.pop("oauth_next", "/")),
            "uri": session.pop("oauth_used_uri", "") or oauth_redirect_uri(),
        }
    return rec


def google_button() -> str:
    """HTML кнопки «Войти через Google» для страниц /login и /register."""
    if not GOOGLE_CLIENT_ID:
        return ""
    return """
    <div class="or-sep"><span>или</span></div>
    <a class="btn-google" href="/auth/login">
      <svg viewBox="0 0 24 24" width="18" height="18"><path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.4a5.5 5.5 0 0 1-2.4 3.6v3h3.9c2.3-2.1 3.6-5.2 3.6-8.8z"/><path fill="#34A853" d="M12 24c3.2 0 6-1.1 8-2.9l-3.9-3c-1.1.7-2.4 1.2-4.1 1.2-3.1 0-5.8-2.1-6.7-5H1.2v3.1A12 12 0 0 0 12 24z"/><path fill="#FBBC05" d="M5.3 14.3a7.2 7.2 0 0 1 0-4.6V6.6H1.2a12 12 0 0 0 0 10.8l4.1-3.1z"/><path fill="#EA4335" d="M12 4.7c1.8 0 3.3.6 4.6 1.8L20 3A12 12 0 0 0 1.2 6.6l4.1 3.1C6.2 6.8 8.9 4.7 12 4.7z"/></svg>
      Продолжить с Google
    </a>
    """


def google_exchange_code(code: str, redirect_uri: str):
    """Обменивает authorization code на access token.

    ВАЖНО: redirect_uri здесь должен быть ровно тем же адресом, что был
    отправлен в Google при авторизации (иначе Google вернёт
    invalid_grant / redirect_uri_mismatch). Поэтому он прокидывается через
    session["oauth_used_uri"], а не вычисляется заново на ходу.
    """
    try:
        r = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri or oauth_redirect_uri(),
            },
            timeout=15,
        )
        if r.status_code != 200:
            app.logger.error("OAuth token exchange failed: %s", r.text)
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
CSE_ERROR_HINTS = {
    "does not have the access to custom search json api": (
        "API включён в одном проекте, а ключ GOOGLE_API_KEY взят из ДРУГОГО проекта. "
        "В Cloud Console сверху выберите проект, где включён Custom Search JSON API, "
        "и создайте API-ключ именно там (Credentials → Create credentials → API key). "
        "Проект ключа виден на странице console.cloud.google.com/apis/credentials."
    ),
    "custom search json api has not been used": (
        "Custom Search JSON API не включено в проекте ключа: Cloud Console → "
        "«API и службы» → «Библиотека» → Custom Search JSON API → Включить."
    ),
    "api key not valid": (
        "GOOGLE_API_KEY неверный или скопирован с пробелами — проверьте значение в .env."
    ),
}


def _cse_error_help(msg: str) -> str:
    low = msg.lower()
    for needle, hint in CSE_ERROR_HINTS.items():
        if needle in low:
            return hint
    if "quota" in low or "limit" in low:
        return ("Превышена квота Custom Search API (бесплатно 100 запросов в день). "
                "Попробуйте завтра или используйте второй ключ.")
    return ""


def _parse_cse(data: dict, page: int, num: int):
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


def duckduckgo_search(query: str, page: int = 1, num: int = NUM_RESULTS, safe: bool = True):
    """Резервный поиск через DuckDuckGo (без ключей, Termux-friendly).

    Автоматически используется, если Google CSE недоступен (ошибки доступа/API),
    чтобы поисковик продолжал работать.
    """
    offset = max(0, (page - 1) * 10)
    last_err = None
    headers = {"User-Agent": "Mozilla/5.0 (Android; Mobile) SearchGPT/1.0"}
    try:
        rr = requests.get("https://duckduckgo.com/", params={"q": query},
                          headers=headers, timeout=10)
        m = re.search(r"vqd=([\d-]+)", rr.text)
        vqd = m.group(1) if m else ""
        r = requests.get(
            "https://duckduckgo.com/i.js",
            params={"q": query, "vqd": vqd, "f": "json", "kl": "ru-es"},
            headers={**headers, "Referer": "https://duckduckgo.com/"},
            timeout=15,
        )
        if r.status_code != 200:
            return {"error": f"DuckDuckGo: HTTP {r.status_code}"}
        results = r.json().get("results", [])
        items = []
        for it in results[offset:offset + num]:
            link = it.get("url", "")
            host = urlparse(link).netloc
            snippet = re.sub(r"<[^>]+>", "", it.get("abstract", "") or "")
            title = re.sub(r"<[^>]+>", "", it.get("title", "") or "")
            items.append({"title": title, "link": link, "snippet": snippet,
                          "displayLink": host, "thumbnail": None})
        if not items:
            return {"error": "DuckDuckGo: пустая выдача"}
        return {
            "items": items,
            "total": len(results),
            "searchTime": None,
            "hasMore": offset + num < len(results),
            "provider": "duckduckgo",
        }
    except (requests.RequestException, ValueError) as e:
        return {"error": f"Резервный поиск недоступен: {e}"}


def google_search(query: str, page: int = 1, num: int = NUM_RESULTS, safe: bool = True):
    """Сначала Google Custom Search API; при ошибке — авто-fallback на DuckDuckGo.

    Ключ и CX можно переопределить в «Настройках» (cse_key/cse_id) — удобно,
    когда ключ из другого проекта или кончилась квота. search_engine=duckduckgo
    полностью отключает Google и использует резервный поиск.
    """
    try:
        st = get_settings()
    except Exception:
        st = dict(SETTINGS_DEFAULTS)
    engine = st.get("search_engine", "auto")
    api_key = st.get("cse_key") or GOOGLE_API_KEY
    cx_id = st.get("cse_id") or GOOGLE_CX_ID

    cse_error = None
    if engine == "duckduckgo":
        return duckduckgo_search(query, page=page, num=num, safe=safe)
    if api_key and cx_id:
        try:
            r = requests.get(
                CSE_URL,
                params={
                    "key": api_key,
                    "cx": cx_id,
                    "q": query,
                    "num": min(num, 10),
                    "start": max(page, 1) * num - num + 1,
                    **({"safe": "active"} if safe else {}),
                },
                timeout=15,
            )
            if r.status_code == 200:
                out = _parse_cse(r.json(), page, num)
                out["provider"] = "google"
                return out
            try:
                msg = r.json().get("error", {}).get("message", r.text)
            except Exception:
                msg = r.text
            cse_error = f"Google API: {msg}"
            help_text = _cse_error_help(msg)
            # Авто-диагностика при ошибках доступа к API: результат кладём в
            # g.cse_diag — страница результатов покажет точный статус и ссылку.
            low = msg.lower()
            if ("does not have the access" in low or "not been used" in low
                    or "access not config" in low):
                try:
                    st_status, st_text = cse_api_diag(api_key)
                    g.cse_diag = {"status": st_status, "text": st_text}
                except Exception:
                    pass
            if help_text:
                cse_error += "\n💡 " + help_text
        except requests.RequestException as e:
            cse_error = f"Сеть недоступна для Google API: {e}"
    else:
        cse_error = "GOOGLE_API_KEY / GOOGLE_CX_ID не настроены в .env"

    # --- Fallback: DuckDuckGo без ключей — поиск работает всегда ---
    ddg = duckduckgo_search(query, page=page, num=num, safe=safe)
    if "items" in ddg:
        ddg["warning"] = (cse_error or "Google CSE недоступен") + \
            "\nПоказаны результаты резервного поиска DuckDuckGo."
        return ddg
    return {"error": cse_error, "help": _cse_error_help(cse_error or "")}

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
# Защита веб-интерфейса: вход через страницу /login (или Google) обязателен.
# На главную, логин и регистрацию пускаем без аккаунта.
# ----------------------------------------------------------------------------
PUBLIC_PATHS = (
    "/auth/login",
    "/auth/callback",
    "/auth/logout",
    "/auth/redirect-uri",  # диагностика redirect_uri_mismatch
    "/login",
    "/register",
    "/api/",              # REST API защищён отдельными ключами
    "/static/",
    "/favicon.ico",
    "/health",
)


@app.before_request
def require_login():
    path = request.path
    if path == "/" or any(path.startswith(p) for p in PUBLIC_PATHS):
        return None
    if not is_signed_in():
        nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login_page", next=nxt))
    return None


@app.context_processor
def inject_user():
    return {"user": get_current_user()}


# ----------------------------------------------------------------------------
# Маршруты авторизации: страницы /login и /register + Google OAuth
# ----------------------------------------------------------------------------
def safe_next(target: str, default: str = "/") -> str:
    """Разрешаем только внутренние редиректы (защита от open-redirect)."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return default


@app.route("/login", methods=["GET", "POST"])
def login_page():
    nxt = safe_next(request.values.get("next", ""))
    error = request.args.get("error", "")
    if error == "state":
        error = "Сессия входа истекла. Нажмите «Продолжить с Google» ещё раз."
    elif error == "cookies":
        error = ("Браузер или прокси не сохранил cookie сайта — войдите через "
                 "обычную форму (логин и пароль) или откройте сайт напрямую.")
    else:
        error = ""
    if request.method == "POST":
        login = request.form.get("login", "").strip()
        password = request.form.get("password", "")
        row = None
        if login and password:
            if "@" in login:
                row = db().execute(
                    "SELECT * FROM users WHERE lower(email)=lower(?) AND provider='local'",
                    (login,),
                ).fetchone()
            else:
                row = db().execute(
                    "SELECT * FROM users WHERE username=? AND provider='local'",
                    (login,),
                ).fetchone()
        if row and verify_password(password, row["pw_hash"], row["pw_salt"]):
            session["user"] = {
                "id": row["id"],
                "name": row["username"],
                "email": row["email"] or "",
                "picture": row["picture"] or "",
                "provider": "local",
            }
            return redirect(nxt)
        error = "Неверный логин или пароль."
    gbtn = Markup(google_button().replace("/auth/login", f"/auth/login?{urlencode({'next': nxt})}")) if google_button() else Markup("")
    return render_template("login.html", error=error, next=nxt, user=get_current_user(), google_btn=gbtn)


@app.route("/register", methods=["GET", "POST"])
def register_page():
    nxt = safe_next(request.values.get("next", ""), default="/")
    error, values = "", {"username": "", "email": ""}
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        values = {"username": username, "email": email}

        if not USERNAME_RE.match(username):
            error = "Имя пользователя: 3–30 символов, только латиница, цифры, точка, _ или -."
        elif len(password) < 6:
            error = "Пароль должен быть не короче 6 символов."
        elif password != password2:
            error = "Пароли не совпадают."
        elif email and "@" not in email:
            error = "Некорректный e-mail."
        else:
            conn = db()
            exists = conn.execute(
                "SELECT 1 FROM users WHERE username=? OR (email!= '' AND lower(email)=lower(?))",
                (username, email),
            ).fetchone()
            if exists:
                error = "Такой пользователь уже зарегистрирован — войдите через /login."
            else:
                pw_hash, pw_salt = hash_password(password)
                cur = conn.execute(
                    "INSERT INTO users (username, email, pw_hash, pw_salt, provider)"
                    " VALUES (?,?,?,?, 'local')",
                    (username, email, pw_hash, pw_salt),
                )
                conn.commit()
                session["user"] = {
                    "id": cur.lastrowid,
                    "name": username,
                    "email": email,
                    "picture": "",
                    "provider": "local",
                }
                return redirect(nxt)
    gbtn = Markup(google_button().replace("/auth/login", f"/auth/login?{urlencode({'next': nxt})}")) if google_button() else Markup("")
    return render_template("register.html", error=error, values=values, next=nxt,
                           user=get_current_user(), google_btn=gbtn)


@app.route("/auth/login")
def login():
    """Вход через Google-аккаунт (OAuth 2.0)."""
    if not GOOGLE_CLIENT_ID:
        return render_template(
            "error.html",
            title="Не настроен вход через Google",
            detail=(
                "В файле .env не заполнены GOOGLE_CLIENT_ID и GOOGLE_CLIENT_SECRET.<br>"
                "Можно войти через обычный аккаунт: <a href='/login'>/login</a> "
                "или <a href='/register'>/register</a>.<br><br>"
                "Создайте OAuth 2.0 клиента на "
                "<a href='https://console.cloud.google.com/apis/credentials'>"
                "console.cloud.google.com/apis/credentials</a> "
                "и укажите Redirect URI: <code>http://localhost:4000/auth/callback</code>."
            ),
        )
    # Проверяем, что redirect_uri хотя бы похож на валидный адрес Google
    # (схема http/https, есть хост). Это ловит опечатки в PUBLIC_BASE_URL до
    # того, как пользователь увидит «недопустимый запрос» от Google.
    uri = oauth_redirect_uri()
    parsed = urlparse(uri)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return render_template(
            "error.html",
            title="Некорректный PUBLIC_BASE_URL",
            detail=(
                f"redirect_uri получился неверным: <code>{uri}</code>.<br>"
                "Проверьте переменную PUBLIC_BASE_URL в .env — она должна быть "
                "вида <code>https://ваш-домен</code> или "
                "<code>http://localhost:4000</code> (без слэша на конце)."
            ),
        )
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state          # запасной вариант (если куки доживут)
    session["oauth_next"] = safe_next(request.args.get("next", ""))
    session["oauth_used_uri"] = uri         # тот же uri используем при обмене кода
    _remember_state(state, request.args.get("next", ""), uri)
    return redirect(build_google_auth_url(state))


@app.route("/auth/redirect-uri")
def redirect_uri_info():
    """Показывает redirect_uri, который приложение отправляет в Google.
    Откройте эту страницу в браузере (по тому адресу, по которому заходите
    на сайт) и скопируйте показанный адрес в Google Cloud Console."""
    uri = oauth_redirect_uri()
    origin = public_origin()
    host = urlparse(origin).hostname or ""
    # полезные варианты для localhost-тестов
    extras = []
    if host in ("localhost", "127.0.0.1"):
        extras = [
            f"http://localhost:{PORT}/auth/callback",
            f"http://127.0.0.1:{PORT}/auth/callback",
        ]
    allowed = (client_id_diagnostic().get("redirect_uris") or [])
    listing = "".join(
        f"<li><code>{u}</code></li>" for u in ([uri] + [e for e in extras if e != uri])
    )
    console_note = ""
    if allowed:
        ok = uri.rstrip("/") in allowed
        console_note = (
            "<br><br>Список URI из консоли Google: "
            + ", ".join(f"<code>{u}</code>" for u in allowed)
            + ("<br>✅ Текущий адрес присутствует в списке."
               if ok else
               "<br>⚠️ Текущего адреса нет в списке — добавьте его.")
        )
    return render_template(
        "error.html",
        title="Ваш OAuth Redirect URI",
        detail=(
            f"Откройте <b>Google Cloud Console → API и сервисы → Учётные данные → "
            f"OAuth 2.0 клиент «Веб-приложение»</b> и добавьте этот адрес в поле "
            f"<b>«Авторизованные URI перенаправления»</b> (сохраните):<br><br>"
            f"<code style='font-size:16px'>{uri}</code><br><br>"
            f"Рекомендуем добавить сразу все:<ul>{listing}</ul>"
            f"Затем подождите 1–2 минуты и войдите заново: "
            f"<a href='/auth/login'>/auth/login</a>.<br><br>"
            f"Если вы открываете сайт через ngrok/cloudflared/cloudpub или по IP — "
            f"добавьте в консоль ровно тот адрес, по которому заходите в браузер "
            f"(сейчас это <code>{origin}</code>).<br><br>"
            f"URL, который уходит в Google прямо сейчас:<br>"
            f"<code style='font-size:12px;word-break:break-all'>"
            f"{build_google_auth_url('DEMO_STATE')}</code>"
            f"{console_note}"
        ),
    )


@app.route("/auth/callback")
def callback():
    # Состояние (state) храним сервером, а не только в cookie: сторонние
    # прокси (cloudpub/ngrok и т.п.) могут терять cookie, и тогда вход
    # отклонялся бы без причины — см. OAUTH_STATES.
    state = request.args.get("state", "")
    if not _state_ok(state):
        return redirect(url_for("login_page", error="state"))
    rec = _state_data(state)
    nxt = rec["next"]
    used_uri = rec.get("uri") or oauth_redirect_uri()
    session.pop("oauth_state", None)
    error = request.args.get("error", "")
    if error == "redirect_uri_mismatch":
        uri = oauth_redirect_uri()
        return render_template(
            "error.html",
            title="Ошибка входа: redirect_uri_mismatch",
            detail=(
                "Google отклонил адрес перенаправления приложения.<br><br>"
                "Добавьте в Google Cloud Console → «URI перенаправления» вашего "
                "OAuth-клиента РОВНО этот адрес (сохраните и подождите ~1 минуту):"
                f"<br><br><code style='font-size:15px'>{uri}</code><br><br>"
                "Если вы добавили его через <a href='/auth/redirect-uri'>"
                "/auth/redirect-uri</a> и ошибка осталась — проверьте, что вход "
                "вы делаете по тому же адресу (https/домен), которому соответствует "
                "этот redirect_uri, или задайте PUBLIC_BASE_URL в .env.<br><br>"
                "<a href='/auth/login'>Попробовать ещё раз</a> | "
                "<a href='/login'>обычный вход</a>"
            ),
        )
    code = request.args.get("code", "")
    if not code:
        detail = "Получен ответ Google без кода авторизации."
        if error:
            detail += f" Код ошибки: <code>{error}</code>"
        return render_template(
            "error.html",
            title="Не удалось войти через Google",
            detail=detail + "<br><br>Попробуйте ещё раз: <a href='/auth/login'>вход через Google</a> или обычный <a href='/login'>/login</a>",
        )
    tokens = google_exchange_code(code, used_uri)
    if not tokens or "access_token" not in tokens:
        return render_template(
            "error.html",
            title="Не удалось обменять код на токен",
            detail=(
                "Google не выдал access token. Частые причины:<br>"
                "• в .env указан неверный GOOGLE_CLIENT_SECRET;<br>"
                "• redirect_uri при обмене отличается от того, что был при авторизации "
                "(проверьте <a href='/auth/redirect-uri'>/auth/redirect-uri</a>);<br>"
                "• код уже использован (обновите страницу входа)."
            ),
        )
    userinfo = google_userinfo(tokens["access_token"]) or {}
    email = userinfo.get("email", "")
    name = userinfo.get("name") or (email.split("@")[0] if email else "Пользователь")
    picture = userinfo.get("picture", "")

    # Привязываем Google-аккаунт к локальной таблице пользователей
    conn = db()
    row = None
    if email:
        row = conn.execute(
            "SELECT * FROM users WHERE lower(email)=lower(?)", (email,)
        ).fetchone()
    if not row:
        base = re.sub(r"[^a-zA-Z0-9._-]", "", name)[:30] or "user"
        uname = base
        suffix = 1
        while conn.execute(
            "SELECT 1 FROM users WHERE username=?", (uname,)
        ).fetchone():
            uname = f"{base}{suffix}"[:30]
            suffix += 1
        pw_hash, pw_salt = hash_password(secrets.token_hex(16))
        cur = conn.execute(
            "INSERT INTO users (username, email, pw_hash, pw_salt, provider, picture)"
            " VALUES (?,?,?,?, 'google', ?)",
            (uname, email, pw_hash, pw_salt, picture),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    elif picture and (row["picture"] or "") != picture:
        conn.execute("UPDATE users SET picture=? WHERE id=?", (picture, row["id"]))
        conn.commit()

    session["user"] = {
        "id": row["id"],
        "name": row["username"],
        "email": email or (row["email"] or ""),
        "picture": picture or (row["picture"] or ""),
        "provider": "google",
        "g_name": name,
    }
    return redirect(nxt if nxt.startswith("/") else "/")


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
        user=get_current_user(),
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
        user=get_current_user(),
        query=query,
        results=results,
        error=error,
        ai=ai,
        page=page,
        ai_enabled=st["ai_enabled"],
        results_per_page_num=st["results_per_page"],
        on_results=True,
        cse_diag=getattr(g, "cse_diag", None),
        cse_enable_link=CSE_ENABLE_LINK,
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
        new["search_engine"] = request.form.get("search_engine", st["search_engine"])
        new["cse_key"] = request.form.get("cse_key", st["cse_key"]).strip()
        new["cse_id"] = request.form.get("cse_id", st["cse_id"]).strip()
        for b in ("safe_search", "ai_enabled", "new_tab", "instant_answers", "sound", "autosuggest"):
            new[b] = request.form.get(b) == "on"
        resp = redirect(url_for("settings_page", saved=1))
        return settings_response(resp, new)

    if request.args.get("saved") == "1":
        saved = True

    # Статус Custom Search JSON API для текущего ключа (для раздела диагностики)
    eff_key = st.get("cse_key") or GOOGLE_API_KEY
    api_status, api_text = ("", "")
    if eff_key:
        try:
            api_status, api_text = cse_api_diag(eff_key)
        except Exception:
            api_status, api_text = ("net_error", "Диагностика недоступна")

    return render_template(
        "settings.html",
        user=get_current_user(),
        st=st,
        saved=saved,
        valid_models=VALID_MODELS,
        valid_langs=VALID_LANGS,
        valid_rpp=VALID_RPP,
        redirect_uri=oauth_redirect_uri(),
        oauth_configured=bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        cse_has_key=bool(eff_key),
        cse_has_cx=bool(st.get("cse_id") or GOOGLE_CX_ID),
        cse_api_status=api_status,
        cse_api_text=api_text,
        cse_sys_ok=st.get("cse_sys_ok"),
        cse_enable_link=CSE_ENABLE_LINK,
    )


@app.route("/settings/diag")
def settings_diag():
    """AJAX-проверки из страницы настроек: check=api | check=cx."""
    st = get_settings()
    check = request.args.get("check", "api")
    key = st.get("cse_key") or GOOGLE_API_KEY
    cx = st.get("cse_id") or GOOGLE_CX_ID
    if check == "cx":
        ok, msg = check_cx_alive(key, cx)
        new_st = dict(st)
        new_st["cse_sys_ok"] = ok
        new_st["cse_sys_checked_at"] = int(time.time())
        resp = jsonify({"ok": ok, "message": msg})
        return settings_response(resp, new_st)
    status, text = cse_api_diag(key)
    return jsonify({
        "status": status,
        "message": text,
        "enable_link": CSE_ENABLE_LINK,
        "hint": _cse_error_help(text) or _cse_error_help(status),
    })


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
    if not is_signed_in() or not get_settings()["instant_answers"]:
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
    uri = oauth_redirect_uri()
    return jsonify(
        {
            "status": "ok",
            "cse_configured": bool(GOOGLE_API_KEY and GOOGLE_CX_ID),
            "oauth_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
            "redirect_uri": uri,
            "ai_provider": "pollinations.ai",
            "ai_configured": AI_ENABLED_DEFAULT,
            "api_keys_loaded": len(SEARCH_API_KEYS),
        }
    )


if __name__ == "__main__":
    print(f"🔎 SearchGPT запущен: http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
