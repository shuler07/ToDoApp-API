from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String

from database import Base, db

class NotesModel(Base):
    __tablename__ = 'notes'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uid: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String)
    text: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)

Base.metadata.create_all(db.get_engine())