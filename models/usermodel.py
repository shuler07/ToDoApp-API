from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String

from database import Base

class UserModel(Base):
    __tablename__ = 'user'

    uid: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String)
    password: Mapped[str] = mapped_column(String)