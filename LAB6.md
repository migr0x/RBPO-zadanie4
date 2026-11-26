# Работа №6. Цепочка сертификатов и HTTPS

Приложение редакции из работы №5 работает на `https://localhost:8443` с TLS 1.3.
Spring Boot загружает хранилище PKCS#12 из `tls/local/lab6-server.p12`.
Конфигурация находится в `src/main/resources/application.yml`.

```text
RBPO Root CA
└── RBPO Issuing CA
    └── RBPO Lab6 Issuing <полный номер студенческого билета>
        └── RBPO Lab6 Server <полный номер студенческого билета>
```

У собственного УЦ `CA:true, pathLen:0` и разрешение подписывать сертификаты.
У сервера `CA:false`, назначение `serverAuth` и SAN для `localhost` и `127.0.0.1`.
Запись `lab6-server` содержит закрытый ключ сервера и всю цепочку. Промежуточный
ключ используется только при выпуске. Учебный корень годен до 19 января 2027 года.
Сроки выдаваемых сертификатов сокращаются по мере приближения срока верхних УЦ.

## Повторный выпуск

Понадобятся JDK 21 или новее и PowerShell. Скачайте учебное промежуточное
хранилище с [официальной страницы курса](https://github.com/MatorinFedor/RBPO-ZIOVPO-2026/blob/master/files/course-issuing-ca.p12).
Пароль `courseca` указан в [условии задания](https://github.com/MatorinFedor/RBPO-ZIOVPO-2026/blob/master/files/zadanie6.pdf).
Публичный учебный корень уже находится в `tls/course-root-ca.crt`.

```powershell
.\scripts\New-Lab6Certificates.ps1 -CourseIssuingStore 'C:\path\course-issuing-ca.p12'
```

Скрипт запросит полный номер студенческого билета, пароль учебного хранилища
и новый пароль серверного PKCS#12. При запуске без интерактивного ввода можно
передать `-StudentId` и задать переменные среды `LAB6_COURSE_CA_PASSWORD` и
`TLS_KEYSTORE_PASSWORD`. Скрипт сверяет оба исходных отпечатка SHA-256, выпускает
сертификаты и проверяет порядок четырёх записей и оба имени. Для повторного
выпуска перенесите старый каталог `tls/local/` в другое место.

Отпечатки, сверенные по [материалам курса](https://github.com/MatorinFedor/RBPO-ZIOVPO-2026#задание-6-создание-цепочки-сертификатов-и-настройка-https):

```text
RBPO Root CA    9A:D6:EC:24:B4:E6:18:A8:2C:4B:F7:E1:9C:8A:F3:F4:E0:22:68:03:A3:97:74:5C:98:79:F7:DC:06:11:36:DF
RBPO Issuing CA CB:5A:38:65:37:04:ED:D8:FA:96:4E:89:7E:FE:53:C4:9C:BD:1B:5C:C4:E2:88:F3:73:0F:92:FB:FC:76:E6:7F
```

Персональные сертификаты, PKCS#12 и пароли остаются в локальных `tls/local/` и
`.env`. В репозитории хранится публичный учебный корень и скрипт выпуска.

## Запуск

Скопируйте `.env.example` в `.env`, если локальный `.env` ещё не подготовлен.
Укажите `TLS_KEYSTORE_PASSWORD` из шага выпуска, случайный `JWT_SECRET`
(минимум 32 байта UTF-8) и параметры PostgreSQL. Параметры подключения снаружи
Docker задаются `DB_URL`, `DB_USERNAME` и `DB_PASSWORD`. Для ручного запуска
с отдельной базой предварительно создайте её и роль, которая сможет применить
миграции Flyway.

```powershell
mvn clean verify
java -jar target/rbpo-lab4-variant27-1.0.0.jar
```

Для запуска со своей базой в Docker заполните также `POSTGRES_*` и `APP_DB_*`
в `.env`, затем выполните `docker compose up --build -d`. Compose использует
собственную БД и монтирует серверный PKCS#12 доступным только для чтения.

## Проверка HTTPS

Импортируйте `tls/course-root-ca.crt` в доверенные центры сертификации отдельного
профиля Firefox и разрешите ему идентификацию сайтов. В Firefox создайте профиль
через `about:profiles`, затем в `about:preferences#privacy` откройте управление
сертификатами и на вкладке центров сертификации выберите импорт. Для отдельно
распакованного Firefox тот же результат даёт политика `Certificates.Install`.
Проверочный адрес — `https://127.0.0.1:8443/api/auth/me`. Без токена сервис
возвращает JSON с HTTP 401. Доступ к закрытому
ключу учебного УЦ дан участникам курса, поэтому для него используется отдельный
профиль. [Настройка Certificates в Firefox](https://firefox-admin-docs.mozilla.org/reference/policies/certificates/)

```powershell
.\scripts\Test-Lab6Https.ps1
postman collection run postman/RBPO_Lab5_Variant27.postman_collection.json --env-var 'baseUrl=https://localhost:8443' --ssl-extra-ca-certs tls/course-root-ca.crt --no-report-events
```

Обе команды проверяют сертификат. Скрипт дополнительно фиксирует версию TLS,
проверяет вход, доступ по Bearer JWT, смену обоих токенов и HTTP 401 при
повторной отправке старого refresh. В Postman Desktop корень можно указать в
Settings → Certificates → CA Certificates, сохранив проверку SSL включённой.

## Результаты проверки 26 ноября 2026 года

- `mvn clean verify` собрал JAR, все 52 теста прошли.
- Рабочий JAR запустился с PostgreSQL 16.15 в отдельной тестовой базе. Flyway
  применил миграции V1–V4. При запросе обычным HTTP тот же порт вернул 400.
- OpenSSL согласовал TLS 1.3, получил четыре сертификата и проверил цепочку и
  имя `localhost` до предоставленного корня. Скрипт HTTPS прошёл для
  `localhost` и `127.0.0.1`. Для каждого прогона PostgreSQL подтвердил одну
  строку `REVOKED` и одну `ACTIVE`.
- Postman выполнил 23 запроса и 80 проверок через HTTPS. Ошибок нет.
- В отдельном профиле Firefox подтверждён импорт учебного корня. Браузер
  открыл `https://127.0.0.1:8443/api/auth/me` и показал ожидаемый JSON с 401.
- Docker Compose не запускался. Приложение проверено из JAR.
