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
import socket
import sqlite3
import ssl
import sys
import threading
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
# Запасные хосты Google API: если основной www.googleapis.com недоступен
# (SSL-ошибки, блокировки прокси/оператора — частая история на Termux),
# пробуем эти адреса.
CSE_FALLBACK_HOSTS = [
    "https://customsearch.googleapis.com/customsearch/v1",
    "https://www.googleapis.com.cn/customsearch/v1",
]
CSE_ENABLE_LINK = ("https://console.cloud.google.com/apis/library/customsearch.googleapis.com"
                   "?project=_")
NUM_RESULTS = 10


def _make_ssl_adapter():
    """HTTPSAdapter с увеличенным числом повторов и собственным SSL-контекстом.

    Ошибка SSLEOFError («EOF occurred in violation of protocol») обычно
    возникает из-за обрыва TLS-соединения посредником (провайдер/прокси/CGNAT).
    Помогает: повторные попытки, короткое живое соединение (Connection: close)
    и запасные хосты.
    """
    try:
        from requests.adapters import HTTPAdapter
        ctx = ssl.create_default_context()
        adapter = HTTPAdapter(max_retries=3, pool_connections=4, pool_maxsize=8)
        return adapter
    except Exception:
        return None


class SearchSession:
    """Обёртка над requests с повторами, таймаутами и перебором хостов."""

    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
            "Accept": "*/*",
            "Accept-Language": "ru,en;q=0.9",
        })
        ad = _make_ssl_adapter()
        if ad is not None:
            self.s.mount("https://", ad)

    def get(self, url, params=None, timeout=15, hosts=None, headers=None):
        """GET с перебором основного + запасных хостов и короткими ретраями."""
        urls = [url] + list(hosts or [])
        last_exc = None
        for u in urls:
            try:
                r = self.s.get(u, params=params, timeout=timeout, headers=headers)
                # 5xx от шлюзов (часто сопровождается обрывом TLS) — пробуем следующий хост
                if r.status_code in (500, 502, 503, 504):
                    last_exc = requests.RequestException(
                        f"HTTP {r.status_code} от {u.split('/')[2]}")
                    continue
                return r
            except requests.RequestException as e:
                last_exc = e
        raise last_exc if last_exc else requests.RequestException("нет URL для запроса")


_http = SearchSession()

# Кеш сетевой доступности: не долбим Google каждые полсекунды, если сеть легла.
_net_cache = {"ok": None, "checked_at": 0.0, "lock": threading.Lock()}
NET_CACHE_TTL = 30  # секунд


def network_check(host="www.googleapis.com", port=443, timeout=4):
    """Быстрая проверка: есть ли вообще выход в интернет к host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def net_ok(refresh=False):
    """Помеченное временем состояние сети (кеш), чтобы не тормозить ответы."""
    now = time.time()
    with _net_cache["lock"]:
        if (not refresh and _net_cache["ok"] is not None
                and now - _net_cache["checked_at"] < NET_CACHE_TTL):
            return _net_cache["ok"]
        ok = network_check()
        _net_cache["ok"] = ok
        _net_cache["checked_at"] = now
        return ok

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
    """Диагностика доступа ключа к Custom Search JSON API — БЕЗ Cloud Billing API.

    Раньше здесь дёргался cloudbilling.googleapis.com, который возвращал
    бесполезную ошибку 403 («requests to this api cloudbilling ... are blocked»)
    и пугал пользователя. Теперь проверка идёт напрямую тем же эндпоинтом,
    которым реально пользуется поиск: один тестовый запрос q="test", num=1.

    Возвращает (status, текст), status:
      'ok'          — ключ имеет доступ к API;
      'invalid_key' — ключ недействителен / удалён;
      'not_enabled' — API не включён в ПРОЕКТЕ КЛЮЧА (частая причина ошибки
                      «does not have the access to Custom Search JSON API»);
      'ip_blocked'  — ключ ограничен списком IP/рефереров;
      'quota'       — исчертана дневная квота;
      'net_error'   — сеть/TLS недоступны;
      'other'       — прочее (текст Google приложен).
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
        r = _http.get(CSE_URL, params={"key": api_key, "q": "test", "num": 1},
                      timeout=15, hosts=CSE_FALLBACK_HOSTS)
        body = ""
        try:
            body = (r.json().get("error", {}) or {}).get("message", "") or ""
        except Exception:
            body = (r.text or "")[:200]
        low = (body + " " + str(r.status_code)).lower()
        if r.status_code == 200:
            result = ("ok", "Ключ имеет доступ к Custom Search JSON API")
        elif "api key not valid" in low or "invalid" in low and "api key" in low:
            result = ("invalid_key", "API-ключ недействителен (проверьте значение в .env)")
        elif "access not configured" in low or "does not have the access" in low \
                or "have not been used" in low or "custom search json api" in low and "disabled" in low:
            result = ("not_enabled",
                      "В проекте этого API-ключа Custom Search JSON API НЕ включён")
        elif "ip referer" in low or "permission denied on resource project" in low \
                and "apikeyservice" in low:
            result = ("ip_blocked",
                      "Ключ ограничен списком IP/HTTP-рефереров в Cloud Console")
        elif "quota" in low or "limit" in low:
            result = ("quota", "Превышена квота API (бесплатно 100 запросов/день)")
        elif r.status_code != 200:
            result = ("other", f"Google вернул HTTP {r.status_code}: {body[:150]}")
    except requests.RequestException as e:
        result = ("net_error", "Сеть недоступна: " + _short_err(e))
    CSE_DIAG_CACHE[ck] = (now, result)
    return result


def check_cx_alive(api_key: str, cx_id: str):
    """Живой мини-тест CX: один запрос к CSE с num=1. Возвращает (ok, сообщение)."""
    if not api_key or not cx_id:
        return (False, "Нужны и ключ, и CX")
    try:
        r = _http.get(CSE_URL, params={"key": api_key, "cx": cx_id,
                                       "q": "test", "num": 1}, timeout=15,
                      hosts=CSE_FALLBACK_HOSTS)
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

# Определяем HTTPS за прокси (cloudpub/ngrok/cloudflared) по X-Forwarded-Proto:
# без этого Flask не ставит на cookie сессии флаг Secure и SameSite=None,
# а браузеры (Safari и др.) такие cookie в HTTPS-контексте отбрасывают —
# вход «сбрасывался» сразу после логина.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


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
        # Ключи админ-панели (создаются в /admin, работают как Bearer-токены)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS admin_keys (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT NOT NULL,
                 key_hash TEXT UNIQUE NOT NULL,
                 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                 expires_at INTEGER DEFAULT 0,
                 revoked INTEGER DEFAULT 0
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
        r = _http.get(
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
        r = _http.s.post(
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
        r = _http.get(
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


def normalize_link(link: str) -> str:
    """CSE иногда отдаёт ссылку без схемы («example.com/page») — такая ссылка
    в браузере открывалась как несуществующая страница нашего же сайта.
    Исправляем: относительные адреса превращаем в https://."""
    link = (link or "").strip()
    if not link:
        return link
    low = link.lower()
    if low.startswith(("http://", "https://", "mailto:", "tel:", "data:", "#")):
        return link
    if link.startswith("//"):
        return "https:" + link
    return "https://" + link


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
                "link": normalize_link(it.get("link", "")),
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
    """Резервный поиск без ключей (Termux-friendly), чтобы поисковик работал
    всегда — автоматически используется, если Google CSE недоступен.

    Порядок: DuckDuckGo HTML-выдача (не требует токенов) →lite DDG → i.js API.
    """
    offset = max(0, (page - 1) * 10)
    headers = {"User-Agent": "Mozilla/5.0 (Android 13; Mobile) SearchGPT/1.0"}
    items = []

    # --- способ 1: обычный HTML-результат DDG -------------------------------
    try:
        r = requests.get("https://duckduckgo.com/html/",
                         params={"q": query}, headers=headers, timeout=12)
        if r.status_code == 200:
            blocks = re.findall(
                r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>'
                r'.*?class="result__snippet"[^>]*>(.*?)</a>',
                r.text, re.S,
            )
            for href, title_html, snip_html in blocks:
                link = href
                m = re.search(r"uddq([^&]+)", link)  # редирект DDG -> чистый URL
                if m:
                    from urllib.parse import unquote
                    link = unquote(m.group(1))
                if not link.startswith(("http", "//")):
                    continue
                title = re.sub(r"<[^>]+>", "", title_html).strip()
                snippet = re.sub(r"<[^>]+>", "", snip_html).strip()
                host = urlparse(link).netloc or ""
                items.append({"title": title, "link": normalize_link(link),
                              "snippet": snippet, "displayLink": host,
                              "thumbnail": None})
    except requests.RequestException:
        pass

    # --- способ 2: lite-версия ----------------------------------------------
    if not items:
        try:
            r = requests.get("https://lite.duckduckgo.com/lite/",
                             params={"q": query}, headers=headers, timeout=12)
            if r.status_code == 200:
                links = re.findall(
                    r'<a[^>]+class="result-link"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                    r.text, re.S)
                snips = re.findall(
                    r'class="result-snippet"[^>]*>(.*?)</td>', r.text, re.S)
                for i, (href, title_html) in enumerate(links):
                    link = href
                    m = re.search(r"uddq([^&]+)", link)
                    if m:
                        from urllib.parse import unquote
                        link = unquote(m.group(1))
                    if not link.startswith(("http", "//")):
                        continue
                    items.append({
                        "title": re.sub(r"<[^>]+>", "", title_html).strip(),
                        "link": normalize_link(link),
                        "snippet": re.sub(r"<[^>]+>", "",
                                          snips[i] if i < len(snips) else "").strip(),
                        "displayLink": urlparse(link).netloc or "",
                        "thumbnail": None})
        except requests.RequestException:
            pass

    # --- способ 3: JSON API (может быть заблокирован) ------------------------
    if not items:
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
            if r.status_code == 200:
                for it in r.json().get("results", []):
                    link = it.get("url", "")
                    items.append({
                        "title": re.sub(r"<[^>]+>", "", it.get("title", "") or ""),
                        "link": normalize_link(link),
                        "snippet": re.sub(r"<[^>]+>", "", it.get("abstract", "") or ""),
                        "displayLink": urlparse(link).netloc or "",
                        "thumbnail": None})
        except (requests.RequestException, ValueError):
            pass

    if not items:
        return {"error": "Резервный поиск не вернул результатов (нет сети?)"}
    page_items = items[offset:offset + num] or items[:num]
    return {
        "items": page_items,
        "total": len(items),
        "searchTime": None,
        "hasMore": offset + num < len(items),
        "provider": "duckduckgo",
    }


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
        # Если сеть к Google недоступна (кеш проверки), не тратим время на
        # таймауты — сразу идём в резервный поиск с понятным предупреждением.
        if not net_ok():
            cse_error = ("Нет соединения с googleapis.com (проверьте Wi-Fi/мобильную сеть; "
                         "на Termux частая причина — прокси оператора или блокировка TLS)")
        else:
            try:
                r = _http.get(
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
                    hosts=CSE_FALLBACK_HOSTS,
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
                # Обновляем кеш сети: возможно, она только что легла/поднялась
                ok_now = net_ok(refresh=True)
                detail = str(e.__cause__ or e)[:300]
                if isinstance(e.__cause__, ssl.SSLError) or "SSL" in type(e).__name__ \
                        or "UNEXPECTED_EOF" in detail or "SSLEOF" in detail:
                    cse_error = (
                        "Соединение с Google API обрывается на уровне TLS "
                        "(SSLEOFError). Это почти всегда сеть/провайдер/прокси, а не "
                        "настройки ключа: попробуйте переключить Wi-Fi ↔ мобильный "
                        "интернет, выключить VPN/прокси или повторить позже. "
                        f"Детали: {detail}"
                    )
                elif not ok_now:
                    cse_error = ("Нет соединения с googleapis.com — проверьте интернет. "
                                 f"Детали: {detail}")
                else:
                    cse_error = f"Сеть недоступна для Google API: {detail}"
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
        r = _http.s.post(
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
    "/admin",              # защищено собственным паролем/ключом (см. ADMIN_PASSWORD)
    "/api/",               # REST API защищён отдельными ключами
    "/static/",
    "/favicon.ico",
    "/health",
)


@app.before_request
def require_login():
    path = request.path
    if path == "/" or any(path.startswith(p) for p in PUBLIC_PATHS):
        return None
    # Подстраховка после логина, если cookie сессии не прижилась в браузере:
    # временный параметр _sid авторизует один переход.
    sid = request.args.get("_sid", "")
    if sid.isdigit() and not is_signed_in():
        row = db().execute(
            "SELECT id, username, email, provider, picture FROM users WHERE id=?",
            (int(sid),),
        ).fetchone()
        if row:
            session["user"] = {
                "id": row["id"], "name": row["username"],
                "email": row["email"] or "", "picture": row["picture"] or "",
                "provider": row["provider"],
            }
            # редирект на ту же страницу БЕЗ _sid — там сессия уже живёт
            clean = request.args.to_dict(flat=True)
            clean.pop("_sid", None)
            target = request.path + (("?" + urlencode(clean)) if clean else "")
            return redirect(target)
    if not is_signed_in():
        nxt = request.full_path if request.query_string else request.path
        return redirect(url_for("login_page", next=nxt))
    return None


@app.after_request
def after_request(resp):
    try:
        resp = fix_login_redirects(resp)
    except Exception:
        pass
    # HTTPS-прокси (cloudpub/ngrok): cookie настроек ставятся вручную, поэтому
    # здесь добавляем им Secure/SameSite=None. Cookie сессии Flask сам делает
    # Secure+SameSite=Lax при HTTPS (см. ProxyFix выше).
    fwd_proto = request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip()
    if fwd_proto == "https":
        patched = []
        had_cookie = False
        for c in resp.headers.getlist("Set-Cookie"):
            had_cookie = True
            if "Secure" not in c:
                c += "; Secure"
            if "SameSite=Lax" in c:
                c = c.replace("SameSite=Lax", "SameSite=None")
            patched.append(c)
        if had_cookie:
            resp.headers.remove("Set-Cookie")
            for c in patched:
                resp.headers.add("Set-Cookie", c)
    return resp


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


def fix_login_redirects(resp):
    """После логина/регистрации браузер может не принять cookie сессии
    (прокси cloudpub/ngrok без HTTPS, Safari в приватном режиме, Termux-браузер) —
    тогда пользователя сразу кидало обратно на /login. Подстраховка: редирект
    главной страницы (/) после входа оставляем чистым, а для защищённых
    внутренних страниц добавляем ?_sid=<id> — по нему require_login авторизует
    переход, даже если cookie не дожили."""
    if resp.status_code == 302 and request.method == "POST":
        uid = session.get("user", {}).get("id") if "user" in session else None
        loc = resp.headers.get("Location", "")
        if uid and loc.startswith("/") and not loc.startswith("//") \
                and "_sid=" not in loc:
            path = urlparse(loc).path
            if path != "/":  # главная и так публичная — не усложняем URL
                sep = "&" if "?" in loc else "?"
                resp.headers["Location"] = f"{loc}{sep}_sid={uid}"
    return resp


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
        return redirect(normalize_link(items[0]["link"]))
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
        try:
            page = int(payload.get("page", 1) or 1)
        except (TypeError, ValueError):
            return jsonify({"error": {"code": 400,
                                      "message": "Параметр 'page' — целое число"}}), 400
        want_ai = bool(payload.get("ai", False))
    else:
        query = request.args.get("q", "").strip()
        try:
            page = int(request.args.get("page", 1) or 1)
        except (TypeError, ValueError):
            return jsonify({"error": {"code": 400,
                                      "message": "Параметр 'page' — целое число"}}), 400
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
            "network_google_reachable": net_ok(),
        }
    )


# ----------------------------------------------------------------------------
# Админ-панель /admin (пароль ADMIN_PASSWORD, по умолчанию 37212)
#   * онлайн-редактор файлов проекта (для .py — проверка синтаксиса, бэкапы),
#   * «ключи редактирования» sgpt-admin-... — REST-доступ к файлам команды,
#   * диагностика Google API / сети / ИИ, перезапуск процесса, пользователи.
# Авторизация: подписанная cookie sgpt_admin (7 дней) ИЛИ заголовок
#   Authorization: Bearer sgpt-admin-... / X-API-Key (см. вкладку «Ключи API»).
# ----------------------------------------------------------------------------
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "37212").strip() or "37212"
ADMIN_COOKIE = "sgpt_admin"
ADMIN_COOKIE_MAX_AGE = 60 * 60 * 24 * 7
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
BACKUP_DIR = os.path.join(PROJECT_ROOT, "backups")
ADMIN_HIDDEN_DIRS = {".git", "__pycache__", "backups", "node_modules", ".venv"}
ADMIN_PROTECTED_FILES = {"users.db", ".env"}  # чтение/запись запрещены


def _sign(value: str) -> str:
    return hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


def admin_cookie_value() -> str:
    exp = int(time.time()) + ADMIN_COOKIE_MAX_AGE
    payload = f"{exp}"
    return f"{payload}.{_sign(payload)}"


def admin_session_ok() -> bool:
    raw = request.cookies.get(ADMIN_COOKIE, "")
    if "." not in raw:
        return False
    payload, sig = raw.rsplit(".", 1)
    if not hmac.compare_digest(_sign(payload), sig):
        return False
    try:
        return int(payload) > time.time()
    except ValueError:
        return False


def make_admin_key(name: str, days: int = 30):
    """Создаёт ключ редактирования. Возвращает (полный_ключ, id). В БД — только хэш."""
    token = "sgpt-admin-" + secrets.token_urlsafe(32)
    kh = hashlib.sha256(token.encode()).hexdigest()
    exp = int(time.time()) + max(1, days) * 86400
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO admin_keys (name, key_hash, expires_at) VALUES (?,?,?)",
            (name.strip()[:60] or "key", kh, exp),
        )
        return token, cur.lastrowid


def admin_key_from_request() -> bool:
    auth = request.headers.get("Authorization", "")
    tok = ""
    if auth.lower().startswith("bearer "):
        tok = auth[7:].strip()
    if not tok:
        tok = request.headers.get("X-API-Key", "").strip()
    if not tok.startswith("sgpt-admin-"):
        return False
    kh = hashlib.sha256(tok.encode()).hexdigest()
    row = db().execute(
        "SELECT id FROM admin_keys WHERE key_hash=? AND revoked=0 AND "
        "(expires_at=0 OR expires_at>?)", (kh, int(time.time()))
    ).fetchone()
    return bool(row)


def is_admin() -> bool:
    return admin_session_ok() or admin_key_from_request()


def require_admin():
    if is_admin():
        return None
    if request.path.startswith("/admin/api/"):
        return jsonify({"error": "unauthorized",
                        "hint": "Нужен заголовок Authorization: Bearer sgpt-admin-..."}), 403
    return None  # страницы покажет форму входа по паролю


def safe_project_path(rel: str):
    """Относит путь к корню проекта; выход за пределы и защита файлов — ValueError."""
    rel = (rel or "").replace("\\", "/").lstrip("/")
    full = os.path.abspath(os.path.join(PROJECT_ROOT, rel))
    if full != PROJECT_ROOT and not full.startswith(PROJECT_ROOT + os.sep):
        raise ValueError("Путь вне проекта")
    parts = rel.split("/")
    if any(p in ADMIN_HIDDEN_DIRS for p in parts[:-1]) or parts[0] in ADMIN_HIDDEN_DIRS:
        raise ValueError("Системная папка недоступна")
    if os.path.basename(full) in ADMIN_PROTECTED_FILES or rel in ADMIN_PROTECTED_FILES:
        raise ValueError("Этот файл защищён от просмотра/изменения")
    return full


def admin_file_tree():
    out = []
    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in ADMIN_HIDDEN_DIRS
                         and not d.startswith(".git"))
        rel_root = os.path.relpath(root, PROJECT_ROOT).replace("\\", "/")
        if rel_root == ".":
            rel_root = ""
        for f in sorted(files):
            if f in ADMIN_PROTECTED_FILES or f.endswith((".pyc", ".db", ".log")):
                continue
            p = os.path.join(rel_root, f) if rel_root else f
            try:
                size = os.path.getsize(os.path.join(root, f))
            except OSError:
                size = 0
            out.append({"path": p, "size": size})
    return out


ADMIN_HTML = r"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Админ-панель — SearchGPT</title>
<style>
:root{--bg:#0f1116;--card:#171a21;--tx:#e8eaed;--mut:#9aa0a6;--acc:#8ab4f8;--ok:#34a853;--bad:#ea4335;--bd:#2a2e37}
@media(prefers-color-scheme:light){:root{--bg:#fff;--card:#f7f8fa;--tx:#202124;--mut:#5f6368;--acc:#1a73e8;--bd:#dadce0}}
*{box-sizing:border-box}body{margin:0;font-family:Roboto,Arial,sans-serif;background:var(--bg);color:var(--tx)}
header{display:flex;gap:12px;align-items:center;padding:14px 20px;border-bottom:1px solid var(--bd)}
header b{font-size:18px}.logo{color:var(--acc)}nav{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap}
nav button{background:none;border:1px solid var(--bd);color:var(--tx);padding:7px 14px;border-radius:20px;cursor:pointer}
nav button.on{background:var(--acc);color:#fff;border-color:var(--acc)}
main{padding:18px;max-width:1200px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px;margin-bottom:14px}
input,textarea,select{background:var(--bg);color:var(--tx);border:1px solid var(--bd);border-radius:8px;padding:9px;font-size:14px;width:100%}
textarea{font-family:monospace;min-height:420px;white-space:pre;tab-size:2}
button.act{background:var(--acc);color:#fff;border:0;padding:9px 16px;border-radius:8px;cursor:pointer;font-size:14px}
button.danger{background:var(--bad)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
.grid{display:grid;grid-template-columns:260px 1fr;gap:14px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
ul.files{list-style:none;padding:0;margin:0;max-height:520px;overflow:auto}
ul.files li a{display:block;color:var(--tx);text-decoration:none;padding:6px 9px;border-radius:7px;font-size:13px}
ul.files li a:hover,ul.files li a.on{background:var(--acc);color:#fff}
.msg{padding:10px 12px;border-radius:8px;margin:8px 0;font-size:14px}
.msg.ok{background:rgba(52,168,83,.15);border:1px solid var(--ok)}
.msg.err{background:rgba(234,67,53,.15);border:1px solid var(--bad)}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:7px;border-bottom:1px solid var(--bd);text-align:left}
code.k{background:var(--bg);padding:2px 6px;border-radius:5px;font-size:12px;word-break:break-all}
.badge{padding:2px 8px;border-radius:10px;font-size:12px;background:var(--bd)}
.hide{display:none}
</style></head><body>
<header><span class="logo"><b>Search</b>GPT</b></span> <b>· админ-панель</b>
<nav id="tabs" class="hide">
<button data-t="files" class="on">📁 Файлы</button>
<button data-t="keys">🔑 Ключи API</button>
<button data-t="diag">🩺 Диагностика</button>
<button data-t="users">👥 Пользователи</button>
<button id="logout">Выйти</button></nav></header>
<main>
<div id="loginCard" class="card hide">
  <h2>Вход в админ-панель</h2>
  <div class="row"><input id="pw" type="password" placeholder="Пароль" style="max-width:300px"></div>
  <div class="row"><button class="act" onclick="login()">Войти</button><span id="loginMsg"></span></div>
</div>

<div id="tab-files" class="tab">
  <div class="grid">
    <div class="card"><h3>Проект</h3><ul class="files" id="fileList"></ul></div>
    <div class="card">
      <div class="row"><b id="curPath">— выберите файл —</b></div>
      <textarea id="editor" spellcheck="false"></textarea>
      <div class="row">
        <button class="act" onclick="saveFile()">💾 Сохранить</button>
        <button class="act" onclick="newFile()">✨ Новый файл</button>
        <span id="fileMsg"></span></div>
    </div>
  </div>
</div>

<div id="tab-keys" class="tab hide">
  <div class="card"><h3>Создать ключ редактирования</h3>
    <div class="row"><input id="keyName" placeholder="Название (например: qwen-agent)" style="max-width:300px">
    <select id="keyDays" style="max-width:140px"><option value="7">7 дней</option><option value="30" selected>30 дней</option><option value="90">90 дней</option></select>
    <button class="act" onclick="createKey()">Создать</button></div>
    <div id="newKeyBox" class="msg ok hide">Скопируйте ключ (он показывается один раз):<br><code class="k" id="newKeyVal"></code>
      <div class="row" style="margin-top:8px"><button class="act" onclick="copyKey()">📋 Копировать</button></div></div>
    <p style="color:var(--mut);font-size:13px">Ключ даёт доступ к файлам сайта через API:<br>
    <code class="k">GET /admin/api/list</code> · <code class="k">GET /admin/api/file?path=app.py</code> ·
    <code class="k">POST /admin/api/write {"path","content"}</code> · <code class="k">POST /admin/api/delete</code> ·
    <code class="k">POST /admin/api/restart</code><br>Авторизация: заголовок <code class="k">Authorization: Bearer sgpt-admin-...</code> (или X-API-Key). Без ключа — 403.</p>
  </div>
  <div class="card"><h3>Активные ключи</h3><table id="keyTable"></table></div>
</div>

<div id="tab-diag" class="tab hide">
  <div class="card"><h3>Состояние сервиса</h3><div id="diagBox">…</div>
    <div class="row" style="margin-top:10px">
      <button class="act" onclick="loadDiag()">🔄 Обновить</button>
      <button class="act danger" onclick="restartApp()">♻️ Перезапустить сервер</button>
      <span id="diagMsg"></span></div></div>
</div>

<div id="tab-users" class="tab hide"><div class="card"><h3>Пользователи</h3><table id="userTable"></table></div></div>
</main>
<script>
const $=s=>document.querySelector(s);
async function api(path,opt={}){
  opt.headers=Object.assign({'Content-Type':'application/json'},opt.headers||{});
  const r=await fetch(path,opt);
  let j=null;try{j=await r.json()}catch(e){}
  if(r.status===401||r.status===403&&!j?.items){$('#tabs').classList.add('hide');$('#loginCard').classList.remove('hide')}
  return {status:r.status,data:j};
}
function setMsg(sel,text,ok=true){$(sel).innerHTML=`<span class="msg ${ok?'ok':'err'}">${text}</span>`}
async function login(){
  const r=await fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({password:$('#pw').value})});
  if(r.ok){$('#loginCard').classList.add('hide');$('#tabs').classList.remove('hide');loadFiles()}
  else setMsg('#loginMsg','Неверный пароль',false);
}
$('#logout')&&$('#logout').onclick=async()=>{await fetch('/admin/logout',{method:'POST'});location.reload()};
document.querySelectorAll('#tabs button[data-t]').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('#tabs button[data-t]').forEach(x=>x.classList.remove('on'));b.classList.add('on');
  document.querySelectorAll('.tab').forEach(t=>t.classList.add('hide'));$('#tab-'+b.dataset.t).classList.remove('hide');
  if(b.dataset.t==='keys')loadKeys();if(b.dataset.t==='diag')loadDiag();if(b.dataset.t==='users')loadUsers();
});
let CUR='';
async function loadFiles(){
  const {data}=await api('/admin/api/list');if(!data)return;
  $('#fileList').innerHTML=(data.files||[]).map(f=>
    `<li><a href="#" data-p="${f.path}" onclick="openFile('${f.path}');return false">${f.path} <small style="color:var(--mut)">${f.size}B</small></a></li>`).join('');
}
async function openFile(p){
  CUR=p;document.querySelectorAll('#fileList a').forEach(a=>a.classList.toggle('on',a.dataset.p===p));
  const {data}=await api('/admin/api/file?path='+encodeURIComponent(p));
  if(data){$('#curPath').textContent=p;$('#editor').value=data.content||''}else setMsg('#fileMsg','Ошибка чтения',false);
}
async function saveFile(){
  if(!CUR)return setMsg('#fileMsg','Сначала выберите файл',false);
  const {status,data}=await api('/admin/api/write',{method:'POST',body:JSON.stringify({path:CUR,content:$('#editor').value})});
  setMsg('#fileMsg',status===200?('✅ '+ (data?.message||'сохранено')):(data?.error||'ошибка'),status===200);
}
async function newFile(){
  const p=prompt('Путь нового файла (например templates/about.html)');if(!p)return;
  const {status,data}=await api('/admin/api/write',{method:'POST',body:JSON.stringify({path:p,content:''})});
  if(status===200){loadFiles();openFile(p)}else alert(data?.error||'ошибка');
}
async function createKey(){
  const {status,data}=await api('/admin/api/keys/create',{method:'POST',
    body:JSON.stringify({name:$('#keyName').value||'key',days:+$('#keyDays').value})});
  if(status===200){$('#newKeyVal').textContent=data.key;$('#newKeyBox').classList.remove('hide');loadKeys()}
  else alert(data?.error||'ошибка');
}
function copyKey(){navigator.clipboard.writeText($('#newKeyVal').textContent)}
async function loadKeys(){
  const {data}=await api('/admin/api/keys');if(!data)return;
  $('#keyTable').innerHTML='<tr><th>Имя</th><th>Создан</th><th>Действует до</th><th></th></tr>'+
   (data.keys||[]).map(k=>`<tr><td>${k.name}</td><td>${k.created_at}</td><td>${k.expires}</td>
   <td><button class="act danger" style="padding:4px 10px" onclick="revokeKey(${k.id})">Отозвать</button></td></tr>`).join('');
}
async function revokeKey(id){await api('/admin/api/keys/revoke',{method:'POST',body:JSON.stringify({id})});loadKeys()}
async function loadDiag(){
  const {data}=await api('/admin/api/diag');if(!data)return;
  $('#diagBox').innerHTML=Object.entries(data).map(([k,v])=>`<div class="row"><span class="badge">${k}</span> <b>${v}</b></div>`).join('');
}
async function restartApp(){
  if(!confirm('Перезапустить Flask-процесс? Незалогиненные сессии сбросятся.'))return;
  const {status,data}=await api('/admin/api/restart',{method:'POST'});
  setMsg('#diagMsg',status===200?('✅ '+(data?.message||'перезапуск через 2 сек')):(data?.error||'ошибка'),status===200);
}
async function loadUsers(){
  const {data}=await api('/admin/api/users');if(!data)return;
  $('#userTable').innerHTML='<tr><th>ID</th><th>Логин</th><th>Email</th><th>Способ</th><th>Создан</th></tr>'+
   (data.users||[]).map(u=>`<tr><td>${u.id}</td><td>${u.username}</td><td>${u.email||'—'}</td><td>${u.provider}</td><td>${u.created_at}</td></tr>`).join('');
}
(async()=>{const r=await api('/admin/api/list');if(r.data){$('#tabs').classList.remove('hide');loadFiles()}})();
</script></body></html>"""


@app.route("/admin", methods=["GET"])
def admin_page():
    if is_admin():
        return Response(ADMIN_HTML, mimetype="text/html")
    return redirect(url_for("admin_login_page"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login_page():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        pw = str(data.get("password", request.form.get("password", "")))
        if hmac.compare_digest(pw, ADMIN_PASSWORD):
            resp = jsonify({"ok": True})
            resp.set_cookie(ADMIN_COOKIE, admin_cookie_value(),
                            max_age=ADMIN_COOKIE_MAX_AGE, httponly=True, samesite="Lax")
            return resp
        return jsonify({"error": "неверный пароль"}), 401
    return Response(ADMIN_HTML, mimetype="text/html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    resp = jsonify({"ok": True})
    resp.delete_cookie(ADMIN_COOKIE)
    return resp


@app.route("/admin/api/list")
def admin_api_list():
    err = require_admin()
    if err:
        return err
    return jsonify({"root": PROJECT_ROOT, "files": admin_file_tree()})


@app.route("/admin/api/file")
def admin_api_file():
    err = require_admin()
    if err:
        return err
    try:
        full = safe_project_path(request.args.get("path", ""))
        if not os.path.isfile(full):
            return jsonify({"error": "файл не найден"}), 404
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            return jsonify({"path": request.args.get("path"), "content": f.read()})
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)[:200]}), 500


@app.route("/admin/api/write", methods=["POST"])
def admin_api_write():
    err = require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    rel = str(data.get("path", ""))
    content = str(data.get("content", ""))
    try:
        full = safe_project_path(rel)
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    if rel.endswith(".py"):
        import ast
        try:
            ast.parse(content)
        except SyntaxError as e:
            return jsonify({"error": f"Синтаксис Python неверен: {e}"
                                   f" (строка {e.lineno}). Файл НЕ сохранён."}), 400
    if os.path.isfile(full):
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            import shutil
            stamp = time.strftime("%Y%m%d-%H%M%S")
            shutil.copy2(full, os.path.join(
                BACKUP_DIR, stamp + "-" + rel.replace("/", "_")))
        except Exception:
            pass
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(content)
    return jsonify({"ok": True, "message": f"Сохранён {rel}"})


@app.route("/admin/api/delete", methods=["POST"])
def admin_api_delete():
    err = require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        full = safe_project_path(str(data.get("path", "")))
        if os.path.isfile(full):
            os.remove(full)
            return jsonify({"ok": True})
        return jsonify({"error": "файл не найден"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 403


@app.route("/admin/api/keys/create", methods=["POST"])
def admin_api_keys_create():
    err = require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    days = int(data.get("days", 30) or 30)
    token, kid = make_admin_key(str(data.get("name", "key")), days)
    return jsonify({"ok": True, "id": kid, "key": token})


@app.route("/admin/api/keys")
def admin_api_keys_list():
    err = require_admin()
    if err:
        return err
    rows = db().execute(
        "SELECT id,name,created_at,expires_at,revoked FROM admin_keys ORDER BY id DESC LIMIT 100"
    ).fetchall()
    return jsonify({"keys": [{
        "id": r["id"], "name": r["name"], "created_at": r["created_at"],
        "expires": time.strftime("%Y-%m-%d", time.localtime(r["expires_at"])) if r["expires_at"] else "∞",
        "revoked": bool(r["revoked"]),
    } for r in rows if not r["revoked"]]})


@app.route("/admin/api/keys/revoke", methods=["POST"])
def admin_api_keys_revoke():
    err = require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    with db() as conn:
        conn.execute("UPDATE admin_keys SET revoked=1 WHERE id=?", (int(data.get("id", 0)),))
    return jsonify({"ok": True})


@app.route("/admin/api/diag")
def admin_api_diag():
    err = require_admin()
    if err:
        return err
    key = GOOGLE_API_KEY
    cx = GOOGLE_CX_ID
    st_status, st_text = cse_api_diag(key) if key else ("no_key", "GOOGLE_API_KEY не задан")
    cx_ok, cx_msg = check_cx_alive(key, cx) if (key and cx) else (False, "cx не задан")
    ai_ok = "?"
    try:
        r = _http.post(POLLINATIONS_URL.rstrip("/") + "/v1/chat/completions",
                       json={"model": POLLINATIONS_MODEL,
                             "messages": [{"role": "user", "content": "ping"}],
                             "max_tokens": 5}, timeout=20)
        ai_ok = "работает" if r.status_code == 200 else f"HTTP {r.status_code}"
    except Exception as e:
        ai_ok = "ошибка: " + _short_err(e)
    return jsonify({
        "google_network": "доступен" if net_ok() else "НЕДОСТУПЕН (TLS/сеть)",
        "cse_api": f"{st_status}: {st_text}",
        "search_system_cx": ("жива: " + cx_msg) if cx_ok else ("проблема: " + cx_msg),
        "oauth_configured": "да" if (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET) else "нет",
        "redirect_uri": oauth_redirect_uri(),
        "ai_pollinations": ai_ok,
        "api_keys_count": len(SEARCH_API_KEYS),
    })


@app.route("/admin/api/users")
def admin_api_users():
    err = require_admin()
    if err:
        return err
    rows = db().execute(
        "SELECT id,username,email,provider,created_at FROM users ORDER BY id DESC LIMIT 200"
    ).fetchall()
    return jsonify({"users": [dict(r) for r in rows]})


@app.route("/admin/api/restart", methods=["POST"])
def admin_api_restart():
    err = require_admin()
    if err:
        return err
    def _do():
        time.sleep(2)
        os.execv(sys.executable, [sys.executable] + sys.argv)
    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"ok": True, "message": "перезапуск процесса через 2 секунды"})


if __name__ == "__main__":
    print(f"🔎 SearchGPT запущен: http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
