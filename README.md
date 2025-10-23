# ToDoApp-API
API для обработки клиентских запросов и доступа к базе данных. Возможности на данный момент:
- Логин / Регистрация пользователей
- Верификация почты пользователя
- Проверка подлинности JWT токенов
- Обновление почты, пароля, никнейма
- Создание, обновление, удаление, получение заметок
### Работает вместе с ToDoApp-WEB, который отвечает за клиентскую часть - пользовательский интерфейс и функционал
###### https://github.com/shuler07/ToDoApp-WEB

## Как запустить
Для запуска потребуется установленный docker
1. Установить репозиторий локально
2. Запустить билд образа API:
   ###### docker build . -t todoapp-api
3. Подтянуть образ postgres:
   ###### docker image pull postgres:latest
4. Подтянуть образ redis:
   ###### docker image pull redis:latest
5. Создать .env файл в корневой папке, который должен выглядеть следующим образом:  
   POSTGRES_USER="<имя пользователя для бд (придумать самому любое)>"  
   POSTGRES_PASSWORD="<пароль пользователя для бд (придумать самому любой)>"  
   URL_DATABASE_POSTGRES="postgresql+psycopg://<POSTGRES_USER>:<POSTGRES_PASSWORD>@postgres:5432/todoapp"
   VERIFICATION_ENABLED="<True/False>" - если хотите включить верификацию почты при регистрации - True, иначе - False
   (не требуется, если VERIFICATION_ENABLED="False") EMAIL_USER="<ваша почта для рассылки писем с верификацией>"
   (не требуется, если VERIFICATION_ENABLED="False") EMAIL_PASSWORD="<специальный пароль для gmail api от вашей почты для рассылки писем с верификацией>"
   
   (для настройки почты для рассылки писем см. документацию [smtplib](https://developers.google.com/workspace/gmail/api/quickstart/python))
7. (не требуется, если VERIFICATION_ENABLED="False") После настройки почты для рассылки писем, в корневой директории уже должен присутствовать файл credentials.json. После этого запустить quickstart.py:
   ###### python quickstart.py
   (выполняется единожды для подключения к вашей почте и создания token.json)
8. Поднять композ из API, postgres и redis:
   ###### docker-compose up -d

После запуска API будет находиться по адресу - http://localhost:8000 документация - http://localhost:8000/docs. Сервер принимает запросы с адреса - http://localhost:5173
Чтобы настроить адреса, с которых сервер принимает запросы, измените middleware в файле main.py, перечислив свои адреса через запятую, в кавычках каждый:
###### allow_origins=["http://my_address:my_port", "..."]
