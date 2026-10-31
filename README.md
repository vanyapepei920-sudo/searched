# 🔎 SearchGPT — собственный поисковик на Flask + Google Custom Search API

Поисковик в стиле Google с ИИ-ответом, входом через Google-аккаунт (OAuth 2.0),
публичным REST API с ключами доступа и тёмной/светлой темой. Работает на **Termux**.

## Возможности
- 🔍 Поиск через **Google Custom Search JSON API** (`GOOGLE_API_KEY` + `GOOGLE_CX_ID`)
- 🤖 **ИИ-ответ** над выдачей: модель получает фрагменты результатов поиска и даёт краткий ответ со ссылками на источники — через бесплатный **Pollinations.AI** (ключ не нужен)
- 🔐 Обязательный **вход через Google-аккаунт** для веб-интерфейса
- ⚙️ **REST API для других проектов** как у OpenAI: без ключа — `403`, с ключом — работает
- 🌗 Тёмная и светлая тема (переключатель в шапке, запоминается в браузере)
- 📱 Адаптивный интерфейс в стиле Google

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
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | OAuth 2.0 клиент (console.cloud.google.com → Credentials). Redirect URI: `http://localhost:4000/auth/callback` |
| `SECRET_KEY` | Ключ подписи сессий Flask |
| `AI_ENABLED`, `POLLINATIONS_URL`, `POLLINATIONS_MODEL` | ИИ-ответ через бесплатный Pollinations.AI (ключ не требуется). `AI_ENABLED=0` — отключить блок ИИ |
| `SEARCH_API_KEYS` | Список ключей через запятую для программного доступа к `/api/v1/*` |
| `PORT` | Порт сервера (по умолчанию 4000) |

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
app.py              # Flask-приложение: поиск, OAuth, ИИ, REST API
templates/          # base.html, index.html, results.html, error.html
static/             # style.css (темы), app.js
.env.example        # шаблон конфигурации -> скопируйте в .env
requirements.txt
```

## Проверка конфигурации
`GET /health` покажет, какие ключи заданы (без вывода самих ключей).
