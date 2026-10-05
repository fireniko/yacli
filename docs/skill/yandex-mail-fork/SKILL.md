---
name: yandex-mail-fork
description: "Установка, подключение и безопасная работа с форком yacli (Яндекс Почта, Календарь, Диск) через MCP в Claude Code и Codex. Use when собираешь этот форк из исходников, подключаешь его как MCP-сервер, входишь в Яндекс (пароль приложения или OAuth), настраиваешь правила разрешений на отправку писем или разбираешь ошибки 401, IMAP, CalDAV. Not for Gmail и не для оригинального NextStat/yacli с самообновлением."
---

# Форк yacli для Яндекс Почты, Календаря и Диска

Это защищённый форк yacli. По сравнению с оригиналом убрано самообновление, команда `mcp install` (запись «skills» в каталоги агентов), переопределения адресов через переменные окружения, plaintext-хранение секретов в release, открытый HTTP-режим MCP. Добавлены белый список хостов Яндекса, проверка редиректов, вход в почту по паролю приложения. Подробности: `docs/SECURITY-FORK.md`.

Установка навыка: скопируй папку `docs/skill/yandex-mail-fork` в `~/.claude/skills/` (Windows: `%USERPROFILE%\.claude\skills\`).

## 1. Сборка (из исходников, готовых бинарников нет)

Нужны: Rust ≥ 1.85, на Windows ещё MSVC Build Tools (рабочая нагрузка «Разработка классических приложений на C++»). `link.exe` из Git — не MSVC.

```bash
git clone <URL этого репозитория> yacli && cd yacli
git checkout hardened
cargo build --release          # бинарник: target/release/yacli(.exe)
```

- Только `--release`. В debug-сборке намеренно ослаблены защиты (файловое хранилище секретов, переопределение хостов для тестов); её нельзя использовать с настоящим аккаунтом.
- Скопируй бинарник в постоянное место вне `target/` (его чистит `cargo clean`) и запомни путь, дальше `<BIN>`.
- Не запускай `curl | sh` и установщики с сайта автора оригинала. Обновление: `git pull`, снова `cargo build --release`, заново скопировать бинарник.

## 2. Вход в Яндекс

Почта и Календарь входят **по паролю приложения**, Диск — по OAuth.

Общее: id.yandex.ru → Безопасность → «Пароли приложений». Пароль показывается один раз. Создавай отдельный пароль на каждую службу.

**Почта.** В настройках Яндекс Почты → «Почтовые программы» включи IMAP. Создай пароль типа «Почта».
```powershell
$bin = "<BIN>"
& $bin account add main <ваш-адрес>@yandex.ru --use --mail-auth-mode app-password
$s = Read-Host "Пароль приложения (Почта)" -AsSecureString
$p = [System.Net.NetworkCredential]::new("", $s).Password
& $bin auth login --service mail --app-password $p
Remove-Variable p,s
& $bin status
```
Так пароль не попадает в историю команд. Хранится он только в системном хранилище (Windows Credential Manager / Keychain / Secret Service). Не передавай пароль в чат, не клади в репозиторий и в конфиги агента. Для существующего аккаунта: `yacli account set-mail-auth app-password`.

**Календарь.** Пароль типа «Календарь», вход так же (`--service calendar`). Яндекс активирует его **через 2–3 часа** после создания; до этого ответ 401. Пересоздавать не нужно, просто подожди.

**Диск (OAuth).** Нужно своё приложение: https://oauth.yandex.ru/client/new/ → тип «для доступа к API» (тип нельзя поменять после создания; у типа «для авторизации» лимит 3 группы прав) → права Диска (`cloud_api:disk.app_folder`, `.info`, `.read`, `.write`) → Callback URI `https://oauth.yandex.ru/verification_code`. ClientID — не секрет; client_secret не нужен (PKCE).
```powershell
& $bin auth login --service disk --client-id <ВАШ_CLIENT_ID>
# откроешь выданную ссылку, нажмёшь «Разрешить», скопируешь код подтверждения:
& $bin auth login --service disk --client-id <ВАШ_CLIENT_ID> --code <КОД>
```
Не используй чужой ClientID: токен выдаётся приложению его владельца.

## 3. Подключение к агентам

**Claude Code:**
```bash
claude mcp add yandex-mail --scope user -- "<BIN>" mcp
```
**Codex** (`~/.codex/config.toml`):
```toml
[mcp_servers.yandex-mail]
command = '<BIN>'
args = ["mcp"]
```
Только stdio (`mcp`). HTTP-режим не нужен; он слушает только loopback.

## 4. Правила разрешений (важно)

Письма — недоверенный ввод: текст письма может содержать инструкции для агента (prompt injection). Читать можно свободно, а действия с побочными эффектами должны требовать твоего подтверждения. Если у Claude Code включён авто-режим (`permissions.defaultMode = "auto"`), без явных правил `ask` отправку может одобрить классификатор без тебя. Поэтому добавь в `~/.claude/settings.json`:

```json
{
  "permissions": {
    "allow": [
      "mcp__yandex-mail__yacli_mail_folders", "mcp__yandex-mail__yacli_mail_list",
      "mcp__yandex-mail__yacli_mail_search", "mcp__yandex-mail__yacli_mail_read",
      "mcp__yandex-mail__yacli_mail_invite_inspect", "mcp__yandex-mail__yacli_account_list",
      "mcp__yandex-mail__yacli_account_current", "mcp__yandex-mail__yacli_auth_status",
      "mcp__yandex-mail__yacli_calendar_calendars", "mcp__yandex-mail__yacli_calendar_events",
      "mcp__yandex-mail__yacli_disk_info", "mcp__yandex-mail__yacli_disk_list"
    ],
    "ask": [
      "mcp__yandex-mail__yacli_mail_send", "mcp__yandex-mail__yacli_mail_send_link",
      "mcp__yandex-mail__yacli_mail_send_published_link", "mcp__yandex-mail__yacli_mail_reply",
      "mcp__yandex-mail__yacli_mail_forward", "mcp__yandex-mail__yacli_mail_mark",
      "mcp__yandex-mail__yacli_mail_move", "mcp__yandex-mail__yacli_mail_trash",
      "mcp__yandex-mail__yacli_mail_attachment_export",
      "mcp__yandex-mail__yacli_mail_invite_create_event", "mcp__yandex-mail__yacli_calendar_create",
      "mcp__yandex-mail__yacli_calendar_delete", "mcp__yandex-mail__yacli_disk_mkdir",
      "mcp__yandex-mail__yacli_disk_upload", "mcp__yandex-mail__yacli_disk_upload_link",
      "mcp__yandex-mail__yacli_disk_download", "mcp__yandex-mail__yacli_disk_publish",
      "mcp__yandex-mail__yacli_disk_unpublish", "mcp__yandex-mail__yacli_activity_undo",
      "mcp__yandex-mail__yacli_doctor_apply_safe"
    ]
  }
}
```
Не затирай существующие списки `allow`/`ask`, а добавь. Имя сервера в правилах должно совпадать с тем, что ты указал в `claude mcp add` (здесь `yandex-mail`). Имена инструментов приходят с подчёркиваниями.

Проверка защиты: вызови отправку письма самому себе. Перед выполнением должно появиться окно подтверждения. Безопасно проверить правило можно через `dry_run=true`: письмо не уйдёт, а запрос разрешения всё равно появится.

Управление письмами: `mail_mark` (прочитано/флажок), `mail_move` (в другую существующую папку, по имени как в `mail_folders`), `mail_trash` (в корзину по атрибуту `\Trash`). Безвозвратного удаления в yacli нет совсем: письмо из корзины можно вернуть, а очистить корзину нужно в веб-интерфейсе Яндекса. Перемещение без поддержки `MOVE` и `UIDPLUS` на сервере отклоняется (обычный `EXPUNGE` не используется). У всех трёх есть `dry_run`.

**Важно для чужих установок:** сервер сам не ограничивает набор инструментов; вся защита от случайной или вызванной письмом отправки держится на правилах `ask` выше. Если форком пользуются несколько людей или он работает без человека, одних правил клиента недостаточно: нужен список разрешённых инструментов на стороне сервера (в этом форке его нет).

**Журнал действий.** yacli ведёт `activity.toml` (Windows: `%APPDATA%\yacli\`). В этом форке он не хранит адреса, темы, тексты, имена файлов и ссылки, только операцию, время и нейтральную сводку. Записи, сделанные до этого изменения, могли содержать содержимое: очистить журнал можно командой `yacli activity clear --yes`.

## 5. Проверка работоспособности

1. `yacli status`: `credential_state` у почты `store_present`.
2. `yacli mail folders`, `yacli mail list --limit 3`.
3. В агенте: вызов `yacli_auth_status`, затем `yacli_mail_list`.
4. Отправка проверяется письмом самому себе с подтверждением (п. 4).

## 6. Частые проблемы

| Симптом | Причина и решение |
|---|---|
| `CalDAV ... status 401` | Пароль «Календарь» ещё не активен (ждать 2–3 часа) или создан другого типа. Нужен именно «Календарь». |
| `calendar `default` not found` | У новых аккаунтов календарь событий называется `events-<число>`, а не `default`. Форк сам берёт первый календарь `events-…`; если нужен другой (например, задачи `todos-…`), укажи id из `yacli calendar calendars` / `yacli_calendar_calendars`. |
| CalDAV 401 при верном, как кажется, пароле | Пароль «Календарь» отличается от пароля «Почта»: на каждую службу нужен свой. Проверка вне yacli: `curl.exe -u логин -X PROPFIND -H "Depth: 0" https://caldav.yandex.ru/` должна вернуть 207 (пароль вводи через stdin/`-K -`, не в командной строке). |
| IMAP не пускает | Не включён IMAP в настройках почты или пароль не типа «Почта»; основной пароль аккаунта не подходит. |
| В списке прав приложения нет почты | Выбран тип «для авторизации» (лимит 3 группы). Для почты используй пароль приложения, как в п. 2. |
| `plaintext file secret backend is disabled in release builds` | Задана `YACLI_SECRET_BACKEND=file`; убери переменную. Секреты только в системном хранилище. |
| `host ... is not allowed` | Адрес IMAP/SMTP/CalDAV/OAuth в конфигурации аккаунта не из белого списка Яндекса. Исправь адрес на `imap.yandex.com`, `smtp.yandex.com`, `caldav.yandex.ru` и т.п. |
| Агент не видит сервер | Перезапусти приложение; проверь `claude mcp list` (должен быть `Connected`). |
| Агент спрашивает разрешение на чтение | Имена в `allow` не совпали с именем сервера; сверь с `mcp__<имя-сервера>__yacli_...`. |
| Сборка очень долго висит | Запускай `cargo build --release` из обычного терминала, а не из конвейера с перенаправлением вывода в другой процесс; обычная сборка занимает минуты. |

## 7. Что нельзя
- Не сохранять пароли приложений, токены, client_secret в репозитории, переменных окружения агента и истории команд.
- Не открывать HTTP-режим MCP наружу (код и так откажет для не-loopback адресов).
- Не включать в аккаунт чужие IMAP/SMTP-хосты: токен или пароль уйдёт на них.
- Не делать отправку без подтверждения: правила `ask` из п. 4 обязательны.
