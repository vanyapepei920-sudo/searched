# 🔎 SearchGPT — собственный поисковик на Flask + Google Custom Search API

Поисковик в стиле Google с ИИ-ответом, входом через Google-аккаунт (OAuth 2.0),
публичным REST API с ключами доступа и тёмной/светлой темой. Работает на **Termux**.

## Возможности
- 🔍 Поиск через **Google Custom Search JSON API** (`GOOGLE_API_KEY` + `GOOGLE_CX_ID`)
- 🤖 **ИИ-ответ** над выдачей: модель получает фрагменты результатов поиска и даёт краткий ответ со ссылками на источники — через бесплатный **Pollinations.AI** (ключ не нужен)
- 🔐 Обязательный **вход через Google-аккаунт** (OAuth 2.0 на чистом `requests`, без authlib)
- ⚙️ **Страница настроек** `/settings`: тема, язык, число результатов на странице, безопасный поиск, модель ИИ, мгновенные ответы на главной, звук, подсказки, открытие ссылок в новой вкладке
- ⚡ REST API для других проектов как у OpenAI: без ключа — `403`, с ключом — работает
- 🌗 Тёмная и светлая тема (переключатель в шапке + настройка, запоминается в браузере)
- 📱 Адаптивный интерфейс в стиле Google

## Зависимости (Termux-friendly)
В `requirements.txt` только pure-python пакеты — `flask`, `requests`, `python-dotenv`.
Никаких нативных компиляций, `authlib` больше **не используется** (его установка на
Termux вызывала ошибку) — Google OAuth реализован вручную на `requests`.

## Установка (Termux)
```bash
pkg install python -y
pip install -r requirements.txt

cp .env.example .env
nano .env          # вставьте свои ключи
python app.py      # сервер на http://localhost:4000
```

## Настройка .env
| Переменная | Назначение |
|---|---|
| `GOOGLE_API_KEY`, `GOOGLE_CX_ID` | Ключ и CX-ID вашего поисковика (programmablesearchengine.google.com) |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | OAuth 2.0 клиент (console.cloud.google.com → Credentials). Redirect URI: `http://localhost:4000/auth/callback` и `http://127.0.0.1:4000/auth/callback` |
| `PUBLIC_BASE_URL` | (опционально) публичный адрес сайта, если открываете не через localhost:4000 — например `https://xxx.ngrok-free.app`. Используется для OAuth redirect_uri |
| `SECRET_KEY` | Ключ подписи сессий Flask |
| `AI_ENABLED`, `POLLINATIONS_URL`, `POLLINATIONS_MODEL` | ИИ-ответ через бесплатный Pollinations.AI (ключ не требуется). `AI_ENABLED=0` — отключить блок ИИ |
| `SEARCH_API_KEYS` | Список ключей через запятую для программного доступа к `/api/v1/*` |
| `PORT` | Порт сервера (по умолчанию 4000) |

### Если при входе через Google ошибка «Error 400: redirect_uri_mismatch»

Google сверяет адрес перенаправления **посимвольно**. Что делать:

1. Откройте в браузере **`http://localhost:4000/auth/redirect-uri`** — страница покажет
   ровно тот redirect_uri, который приложение отправляет в Google (там же кнопка «Копировать»,
   адрес также виден в `/health`).
2. В Google Cloud Console → «Учётные данные» → ваш OAuth-клиент «Веб-приложение» →
   «Авторизованные URI перенаправления» → **Добавить URI** и вставьте скопированный адрес.
   Добавьте оба варианта: с `localhost` и с `127.0.0.1`.
3. Сохраните, подождите 1–2 минуты и войдите заново (`/auth/login`).

Важно: адрес в консоли должен совпадать с тем, по которому вы реально открываете сайт.
Если сайт доступен извне (ngrok / cloudflared / IP локальной сети), задайте этот адрес
в `.env` через `PUBLIC_BASE_URL` и добавьте его же в консоль.

Генерация значений: `openssl rand -hex 32` (SECRET_KEY), `openssl rand -hex 24` (API-ключ).

## REST API (для других проектов)
Авторизация — как у OpenAI: заголовок `Authorization: Bearer <ключ>`
(или `X-API-Key: <ключ>`, или `?key=<ключ>`). Без ключа возвращается **403**.

```bash
# поиск
curl "http://localhost:4000/api/v1/search?q=термохромная+краска&ai=1" \
     -H "Authorization: Bearer sk-test-1234567890abcdef"

# только ИИ-ответ с источниками
curl "http://localhost:4000/api/v1/answer?q=что+такое+termux" \
     -H "Authorization: Bearer sk-test-1234567890abcdef"

# список «моделей»
curl http://localhost:4000/api/v1/models -H "Authorization: Bearer sk-test-1234567890abcdef"
```

Пример использования из Python-проекта:
```python
import requests
r = requests.get("http://localhost:4000/api/v1/search",
                 params={"q": "python flask termux", "ai": 1},
                 headers={"Authorization": "Bearer sk-test-1234567890abcdef"})
print(r.json()["items"][0]["link"])
```

## Структура проекта
```
app.py              # Flask-приложение: поиск, OAuth (без authlib), ИИ, настройки, REST API
templates/          # base.html, index.html, results.html, settings.html, error.html
static/             # style.css (темы + страница настроек), app.js
.env.example        # шаблон конфигурации -> скопируйте в .env
requirements.txt    # flask, requests, python-dotenv (Termux-friendly)
```

## Настройки пользователя (/settings)
Всё сохраняется в cookie браузера и применяется сразу:
- 🌗 Тема (тёмная/светлая), язык интерфейса, число результатов на странице (5/10/20)
- 🤖 Вкл/выкл «Ответ ИИ», выбор модели Pollinations (openai/mistral/llama/deepseek/searchgpt)
- ⚡ Мгновенный ответ ИИ прямо на главной (эндпоинт `/api/v1/instant`), звук при ответе
- 🔒 Безопасный поиск Google, открытие результатов в новой вкладке, подсказки по истории поиска

## URL поиска — как у Google
Страница результатов полностью повторяет интерфейс Google (шапка с логотипом и строкой
поиска, вкладки «Все / Картинки / Новости / Видео / Карты», панель знаний справа,
пагинация «SearchGPT 1 2 3…», подвал). Запрос можно передавать тремя способами:
```
http://localhost:4000/search?=Ваш+запрос     # точь-в-точь как у Google
http://localhost:4000/search?search=Ваш+запрос
http://localhost:4000/search?q=Ваш+запрос    # старый вариант тоже работает
```

## Админ-панель (/admin)

Откройте `http://localhost:4000/admin` и войдите по паролю (по умолчанию **37212**,
задаётся переменной `ADMIN_PASSWORD` в `.env`). Возможности:

* **📁 Файлы** — онлайн-редактор кода проекта (для .py — проверка синтаксиса, бэкапы в `backups/`);
* **🔑 Ключи API** — создание «ключей редактирования» `sgpt-admin-...` для удалённого
  управления файлами через REST (Bearer/X-API-Key; отзыв в любой момент);
* **🩺 Диагностика** — статус Google CSE API, поисковой системы CX, сети, OAuth, Pollinations AI;
* **♻️ Перезапуск** сервера одним кнопкой; **👥 Пользователи** — список аккаунтов.

```bash
curl -H "Authorization: Bearer sgpt-admin-XXXX" http://localhost:4000/admin/api/list
curl -H "Authorization: Bearer sgpt-admin-XXXX" "http://localhost:4000/admin/api/file?path=app.py"
curl -X POST -H "Authorization: Bearer sgpt-admin-XXXX" -H "Content-Type: application/json" \
     -d '{"path":"static/x.txt","content":"hello"}' http://localhost:4000/admin/api/write
```

Без ключа все `/admin/api/*` отвечают **403**. Файлы `.env` и `users.db` закрыты от просмотра.

## Проверка конфигурации
`GET /health` покажет, какие ключи заданы (без вывода самих ключей).
