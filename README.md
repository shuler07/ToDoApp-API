# ToDoApp API
## Как запустить
#### API подключается через переменные окружения к заданным postgres и redis датабазам.
#### Для корректного запуска рекомендуется использовать Docker:
1. Установить репозиторий локально (установить python и docker, если еще не установлены)
2. Запустить билд образа API:
   ###### docker build -t todoapp-api .
3. Подтянуть образ postgres:
   ###### docker image pull postgres:latest
4. Подтянуть образ redis:
   ###### docker image pull redis:latest
5. Создать .env файл в корневой папке, который должен выглядеть следующим образом:  
   POSTGRES_USER="имя пользователя для бд (придумать самому любое)"  
   POSTGRES_PASSWORD="пароль пользователя для бд (придумать самому любой)"
   POSTGRES_DB="название базы данных (придумать самому любое)"  
   HOST_REDIS="redis"  
   PORT_REDIS="6379"  
   URL_DATABASE="postgresql+psycopg://{POSTGRES_USER, без скобок}:{POSTGRES_PASSWORD, без скобок}@postgres:5432/{POSTGRES_DB, без скобок}"  
7. Поднять композ из API, postgres и redis:
   ###### docker-compose up -d

#### После запуска API будет находиться по адресу - http://localhost:8000 документация - http://localhost:8000/docs. Сервер принимает запросы с адреса - http://localhost:5173
#### Чтобы настроить адреса, с которых сервер принимает запросы, измените middleware в файле main.py, перечислив свои адреса через запятую, в кавычках каждый:
###### allow_origins=["http://my_address:my_port", "..."]
