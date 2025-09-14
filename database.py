from typing import Annotated

from fastapi import Depends

from sqlalchemy.orm import sessionmaker, Session, DeclarativeBase
from sqlalchemy import create_engine

class Database:

    def __init__(self):
        # format: <db_type>://<user>:<password>@<host>:<port>/<db_name>
        URL_DATABASE = 'postgresql+psycopg2://postgres:1029384756qq@localhost:5432/todoapp'
        
        self.engine = create_engine(URL_DATABASE)
        self.session = sessionmaker(self.engine, expire_on_commit=False)

    def get_engine(self):
        return self.engine

    def get_session(self):
        with self.session() as ses:
            yield ses

db = Database()

# Base class for all databases to create with one command
class Base(DeclarativeBase): pass

sessionDep = Annotated[Session, Depends(db.get_session)]