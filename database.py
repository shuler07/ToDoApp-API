from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine

# Base class for all databases to create with one command
Base = declarative_base()

# format: <db_type>://<user>:<password>@<host>:<port>/<db_name>
URL_DATABASE = 'postgresql+psycopg2://postgres:1029384756qq@localhost:5432/todoapp'

engine = create_engine(URL_DATABASE)
session = sessionmaker(engine, expire_on_commit=False)

def get_session():
    with session() as ses:
        yield ses