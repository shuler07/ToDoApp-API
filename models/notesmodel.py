from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String

from database import Base

class NotesModel(Base):
    __tablename__ = 'notes'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uid: Mapped[int] = mapped_column(Integer)
    note: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)