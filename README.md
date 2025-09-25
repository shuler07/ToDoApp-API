# ToDoApp API
## Как запустить
API подключается через переменные окружения к заданным postgres и redis датабазам.
Для корректного запуска можно использовать 2 варианта:
### Вариант без Docker
1. Установить репозиторий локально (установить python, если нет)
2. Создать виртуальное окружение: python -m venv .venv
3. Скачать зависимости: pip install -r requirements.txt
4. Создать .env файл, в котором задать на отдельных строках
   URL_DATABASE=... (ваш адрес postgres)
   HOST_REDIS=... (ваш хост redis)
   PORT_REDIS=... (ваш порт redis)
5. Запустить сервис: uvicorn main:app

### Вариант с Docker (рекомендуется)
1. Установить репозиторий локально (установить python, docker если нет)
2. Запустить билд образа API: docker build -t todoapp-api .
3. Подтянуть образ postgres: docker image pull postgres:latest
4. Подтянуть образ redis: docker image pull redis:latest
5. Поднять композицию из API, postgres и redis: docker-compose up -d

После запуска API будет находится по адресу http://localhost:8000
