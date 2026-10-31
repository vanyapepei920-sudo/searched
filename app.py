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
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    Markup,
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

# Публичный адрес приложения для OAuth redirect_uri.
# Нужен, когда сайт открыт не напрямую с localhost:4000 (например через
# ngrok / cloudflared / свой домен или по IP локальной сети): Google сверяет
# redirect_uri строго посимвольно и выдаёт "Error 400: redirect_uri_mismatch",
# если в консоли Cloud указан другой адрес.
#   PUBLIC_BASE_URL=https://abc123.ngrok-free.app
# Если оставить пустым — адрес вычисляется автоматически из запроса.
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")


def oauth_redirect_uri() -> str:
    """redirect_uri, который реально уходит в Google (и должен быть в консоли)."""
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL + "/auth/callback"
    # авто-определение: учитываем X-Forwarded-Proto/Host от прокси (ngrok и т.п.)
    fwd_host = request.headers.get("X-Forwarded-Host")
    if fwd_host:
        scheme = request.headers.get("X-Forwarded-Proto", "https").split(",")[0].strip()
        return f"{scheme}://{fwd_host}/auth/callback"
    try:
        return url_for("callback", _external=True)
    except RuntimeError:
        base = request.url_root.rstrip("/")
        return base + "/auth/callback"

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


def build_google_auth_url(state: str, next_url: str = "/") -> str:
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": oauth_redirect_uri(),
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


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
                "redirect_uri": oauth_redirect_uri(),
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
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    session["oauth_next"] = safe_next(request.args.get("next", ""))
    return redirect(build_google_auth_url(state))


@app.route("/auth/redirect-uri")
def redirect_uri_info():
    """Показывает redirect_uri, который приложение отправляет в Google.
    Откройте эту страницу в браузере и скопируйте адрес в Google Cloud Console."""
    uri = oauth_redirect_uri()
    return render_template(
        "error.html",
        title="Ваш OAuth Redirect URI",
        detail=(
            f"Откройте <b>Google Cloud Console → API и сервисы → Учётные данные → "
            f"OAuth 2.0 клиент «Веб-приложение»</b> и добавьте этот адрес в поле "
            f"<b>«Авторизованные URI перенаправления»</b> (сохраните):<br><br>"
            f"<code style='font-size:16px'>{uri}</code><br><br>"
            f"Затем подождите 1–2 минуты (консоль обновляет настройки не мгновенно) "
            f"и войдите заново: <a href='/auth/login'>/auth/login</a>.<br><br>"
            f"Если вы открываете сайт через ngrok/cloudflared или по IP — добавьте "
            f"в консоль ровно тот адрес, по которому заходите в браузер."
        ),
    )


@app.route("/auth/callback")
def callback():
    nxt = session.pop("oauth_next", "/")
    if request.args.get("state") != session.get("oauth_state"):
        return redirect(url_for("login_page"))
    error = request.args.get("error", "")
    if error == "redirect_uri_mismatch":
        return render_template(
            "error.html",
            title="Ошибка входа: redirect_uri_mismatch",
            detail=(
                "Google отклонил redirect_uri приложения.<br><br>"
                "Перейдите на <a href='/auth/redirect-uri'>/auth/redirect-uri</a>, "
                "скопируйте показанный адрес и добавьте его в Google Cloud Console "
                "в раздел «URI перенаправления» вашего OAuth-клиента."
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
    tokens = google_exchange_code(code)
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
        user=get_current_user(),
        st=st,
        saved=saved,
        valid_models=VALID_MODELS,
        valid_langs=VALID_LANGS,
        valid_rpp=VALID_RPP,
        redirect_uri=oauth_redirect_uri(),
        oauth_configured=bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
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
    # redirect_uri считаем вручную (вне request-контекста url_for недоступен)
    if PUBLIC_BASE_URL:
        uri = PUBLIC_BASE_URL + "/auth/callback"
    else:
        try:
            uri = url_for("callback", _external=True)
        except RuntimeError:
            uri = f"http://localhost:{PORT}/auth/callback"
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
