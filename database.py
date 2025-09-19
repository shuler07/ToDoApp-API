from typing import AsyncGenerator, Annotated
from fastapi import Depends

from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio.engine import create_async_engine
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession, AsyncEngine

from os import environ

# Base class for all databases to create with one command
class Base(DeclarativeBase): pass

class Database:
    def __init__(self, url: str | None = environ.get('URL_DATABASE')) -> None:
        if url is None:
            raise ValueError('URL of database not found')

        self.engine: AsyncEngine = create_async_engine(url=url)
        self.session: async_sessionmaker[AsyncSession] = async_sessionmaker(bind=self.engine, expire_on_commit=False)

    def get_engine(self) -> AsyncEngine:
        return self.engine

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        async with self.session() as ses:
            yield ses

    async def create_all_tables(self) -> None:
        async with self.get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

db = Database()

sessionDep = Annotated[AsyncSession, Depends(db.get_session)]