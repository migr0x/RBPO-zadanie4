# РБПО — лабораторная работа №5

**Вариант 27. Редакция новостного издания**

Java 21 · Spring Boot 3.5.5 · Spring Security · JWT HS256 · Spring Data JPA · PostgreSQL 16 · Flyway · Maven

## Назначение

Работа №5 продолжает работу №4 в том же репозитории. К существующему API редакции добавлены access/refresh JWT, серверный учёт выданных пар и однократное обновление refresh-токена. CRUD пяти сущностей, редакционные бизнес-операции, BCrypt, роли и проверки состояния аккаунта сохранены. Имя Maven-артефакта и пакет `ru.mtusi.rbpo.lab4` сохранены для совместимости; точка входа — `RbpoLab4Application`.

## Контракт аутентификации

| Метод и путь | JSON-тело | Успешный статус |
|---|---|---|
| `POST /auth/login` | `username`, `password`, необязательный `deviceId` | `200` |
| `POST /auth/register` | `username`, `displayName`, `email`, `password`, необязательный `deviceId` | `201` |
| `POST /auth/refresh` | `refreshToken` | `200` |

Каждый успешный ответ содержит пару:

```json
{
  "accessToken": "<JWT_ACCESS_TOKEN>",
  "refreshToken": "<JWT_REFRESH_TOKEN>"
}
```

Пример входа:

```http
POST /auth/login
Content-Type: application/json

{
  "username": "chief_editor",
  "password": "EditorDemo!2026",
  "deviceId": "postman-lab5-demo"
}
```

Access передаётся в заголовке `Authorization: Bearer <accessToken>` защищённого запроса, например `GET /api/auth/me` или `GET /api/articles`. Refresh передаётся только в JSON-теле `POST /auth/refresh`. Этот endpoint работает без access и повторного пароля, в том числе при устаревшем или неверном Bearer-заголовке.

Оба JWT подписываются HS256. Для каждого токена создаётся новый `jti`; обязательны `sub`, `jti`, `iat`, `exp` и `type`. Тип равен `access` или `refresh`. Подпись, обязательные claims, срок действия и тип проверяются отдельно: refresh нельзя использовать как Bearer-access, а access — для обновления пары. Времена в БД соответствуют `exp` JWT с секундной точностью. По умолчанию access действует 15 минут, refresh — 7 дней.

## Учёт refresh-сессий

Миграция `V4` создаёт таблицу `user_sessions`:

| Поле | Тип БД | Смысл |
|---|---|---|
| `id` | `UUID`, первичный ключ | Идентификатор выданной пары |
| `username` | строка, `NOT NULL` | Владелец пары |
| `device_id` | строка, допускает `NULL` | Метка клиента |
| `access_token` | `TEXT NOT NULL` | Выданный access JWT |
| `refresh_token` | `TEXT NOT NULL UNIQUE` | Выданный refresh JWT |
| `access_token_expiry` | время, `NOT NULL` | Срок access |
| `refresh_token_expiry` | время, `NOT NULL` | Срок refresh |
| `status` | строка, `NOT NULL` | `ACTIVE`, `USED` или `REVOKED` |

Вход или регистрация возвращают пару после сохранения строки `ACTIVE`. Регистрация пользователя и сохранение сессии входят в общую транзакцию: при ошибке сохранения не остаётся зарегистрированной учётной записи без выданной пары.

При обновлении сервис проверяет JWT, находит и блокирует строку сессии, проверяет владельца и актуальное состояние пользователя, статус `ACTIVE` и `refresh_token_expiry > now`. Прежняя строка получает `USED`, новая пара сохраняется в новой строке `ACTIVE` с теми же владельцем и `deviceId`. Всё выполняется одной транзакцией; техническая ошибка сохранения новой пары откатывает изменение старой строки.

Блокировка строки не позволяет двум параллельным запросам успешно обменять один refresh. При повторной отправке ещё действующего токена из строки `USED` эта строка переводится в `REVOKED`; изменение фиксируется, а ответ имеет статус `401` без новой пары. Отозванный refresh также получает `401`. Отзыв прежней строки не отзывает всю цепочку обновлений и access-токены; новая строка остаётся `ACTIVE`.

Таблица создаётся Flyway от имени сервисного пользователя БД. Существующий `db/init/10-create-app-user.sh` предоставляет ему `USAGE, CREATE` для схемы `public`. Владелец созданной таблицы имеет необходимые права чтения, добавления и изменения строк.

## Регистрация, роли и отказы

Проверки работы №4 сохранены: имя и email уникальны без учёта регистра; поля проверяются Bean Validation; пароль должен содержать 12–72 байта UTF-8, строчные и прописные латинские буквы, цифру и специальный символ. Сервер назначает только `JOURNALIST` и `ACTIVE`: переданное клиентом поле `role` не повышает полномочия.

| Ситуация | Статус |
|---|---|
| Неверный логин/пароль, заблокированная или отключённая учётная запись | `401` |
| Отсутствующее, пустое или неверно оформленное обязательное поле | `400` |
| Неверный, просроченный или неподходящий по типу refresh JWT | `401` |
| Неизвестная, использованная или отозванная refresh-сессия | `401` |
| Повторная регистрация существующего имени или email | `409` |
| Недостаточные полномочия для защищённой операции | `403` |

Ошибка содержит JSON `ApiError` без новой пары токенов.

Правила работы №4 действуют и при Bearer-аутентификации: журналист управляет собственными неопубликованными статьями, редактор управляет рубриками, пользователями, проверками и выпусками. Состояние аккаунта проверяется по БД при Bearer-запросах и обновлении пары.

## Совместимость с работой №4

Для существующих клиентов сохранены HTTP Basic и маршруты `/api/auth/csrf`, `/api/auth/register`, `/api/auth/me`. Регистрация по старому `/api/auth/register` возвращает прежний DTO пользователя. Новый контракт с парой реализован по `/auth/register`.

Basic-запросы изменения по-прежнему требуют CSRF-токен из `GET /api/auth/csrf`, заголовок `X-CSRF-TOKEN` и связанную cookie `JSESSIONID`. Новые `/auth/login`, `/auth/register`, `/auth/refresh` и запросы с Bearer не требуют CSRF-cookie. JWT передаются явно в JSON или заголовке и не используются как cookie-аутентификация.

Миграции `V1`–`V3` сохранены. Обычный следующий коммит добавляет работу №5 поверх работы №4; предыдущая версия доступна в истории Git.

## Запуск

Нужны JDK 21 или новее, Maven и PostgreSQL 16.

1. Создайте локальный `.env`:

   ```powershell
   Copy-Item .env.example .env
   ```

2. Укажите реальные локальные параметры БД. Для продолжения работы с БД работы №4 можно использовать те же `DB_URL`, `DB_USERNAME`, `DB_PASSWORD`. Flyway применит только новую миграцию `V4`.

3. Сгенерируйте секрет подписи:

   ```powershell
   $jwtBytes = New-Object byte[] 48
   $jwtRng = [Security.Cryptography.RandomNumberGenerator]::Create()
   $jwtRng.GetBytes($jwtBytes)
   [Convert]::ToBase64String($jwtBytes)
   $jwtRng.Dispose()
   ```

   Скопируйте полученную строку в `JWT_SECRET` внутри `.env`. Она используется как исходная строка UTF-8; требуется не менее 32 байт. Значение в шаблоне оставлено пустым, случайный секрет в репозиторий не включается. `JWT_ACCESS_TTL=PT15M` и `JWT_REFRESH_TTL=P7D` задают сроки в формате ISO-8601. Секрет должен сохраняться между перезапусками для проверки ранее выданных токенов.

4. Запустите приложение:

   ```powershell
   mvn spring-boot:run
   ```

   Либо откройте `pom.xml` в IntelliJ IDEA и запустите `RbpoLab4Application` с рабочим каталогом проекта.

Для отдельной демонстрационной БД и приложения доступен Docker Compose:

```powershell
docker compose up --build -d
```

Базовый адрес — `http://localhost:8080`. Демо-учётные записи миграции `V3`:

| Логин | Пароль | Роль |
|---|---|---|
| `chief_editor` | `EditorDemo!2026` | `EDITOR` |
| `journalist_ivan` | `JournalistDemo!2026` | `JOURNALIST` |
| `journalist_anna` | `JournalistDemo!2026` | `JOURNALIST` |

## Проверка через Postman

Новая коллекция — `postman/RBPO_Lab5_Variant27.postman_collection.json`. Она запускается сверху вниз и содержит:

1. Вход, защищённый запрос с access, обновление пары с проверкой отличия обоих токенов, отказ при повторном старом refresh и повторном отозванном refresh, доступ с новой парой после отказа.
2. Негативные сценарии входа, обязательных полей, неверного JWT, подмены подписи и взаимозамены типов access/refresh.
3. Регистрацию с немедленной выдачей пары, проверку роли `JOURNALIST` при попытке передать `EDITOR`, отказ при дубликате и нарушения валидации.

В коллекции сохранены только пустые переменные для выданных токенов. Они заполняются во время прогона. Имена регистрируемых пользователей получают уникальный суффикс, поэтому коллекцию можно запускать повторно.

Запуск Postman CLI без отправки результатов во внешний workspace:

```powershell
postman collection run postman/RBPO_Lab5_Variant27.postman_collection.json --no-report-events
```

При другом адресе:

```powershell
postman collection run postman/RBPO_Lab5_Variant27.postman_collection.json --env-var "baseUrl=http://localhost:8081" --no-report-events
```

Старая коллекция `postman/RBPO_Lab4_Variant27.postman_collection.json` сохранена для CRUD, редакционного workflow и прежнего Basic/CSRF-контракта.

## Проверка состояния БД

После первого login должна существовать строка `ACTIVE`. После refresh у неё должен быть статус `USED`, а у новой строки — `ACTIVE`. После повторной отправки старого refresh первая строка должна стать `REVOKED`, вторая остаться `ACTIVE`; число строк этой цепочки остаётся равным двум.

Коллекция задаёт уникальную метку `deviceId` вида `postman-lab5-...` в переменной `workflowDeviceId` и выводит её в Postman Console без токенов. Подставьте её в запрос:

```sql
SELECT id, username, device_id, status,
       access_token_expiry, refresh_token_expiry
FROM public.user_sessions
WHERE device_id = 'postman-lab5-ЗНАЧЕНИЕ_ИЗ_КОЛЛЕКЦИИ';

SELECT status, COUNT(*)
FROM public.user_sessions
WHERE device_id = 'postman-lab5-ЗНАЧЕНИЕ_ИЗ_КОЛЛЕКЦИИ'
GROUP BY status;
```

После полного workflow ожидаются две строки: одна `REVOKED`, одна `ACTIVE`. Сами токены для этой проверки выводить не требуется.

Проверка прав сервисного пользователя (выполнить при подключении под `news_app`):

```sql
SELECT current_user,
       has_table_privilege(current_user, 'public.user_sessions', 'SELECT') AS can_read,
       has_table_privilege(current_user, 'public.user_sessions', 'INSERT') AS can_insert,
       has_table_privilege(current_user, 'public.user_sessions', 'UPDATE') AS can_update;
```

Проверка ограничений:

```sql
SELECT conname, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = 'public.user_sessions'::regclass;
```

## Автоматические тесты

```powershell
mvn clean test
```

Сохранены проверки CRUD, бизнес-операций, Basic, BCrypt, CSRF, ролей и блокировки из работы №4. Для работы №5 добавлены проверки JWT и интеграционные сценарии выдачи, обновления, повторного использования, конкурентного обмена и отката при ошибках сохранения.

Тестовый профиль использует H2 в режиме совместимости с PostgreSQL. Он проверяет приложение и транзакции в тестовой СУБД. Прогон коллекции с обычным профилем проверяет HTTP-контракт работающего приложения с PostgreSQL; миграции и состояние строк дополнительно проверяются SQL-запросами выше. Сведения о выполненных проверках приведены в `TESTING.md`.
