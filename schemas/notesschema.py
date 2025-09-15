from pydantic import BaseModel, Field
from schemas.userschema import UserAuthSchema

class CreateNoteSchema(BaseModel):
    access_token: str
    title: str = Field(min_length=1)
    text: str = Field(min_length=1)

class ChangeNoteStatusSchema(UserAuthSchema):
    id: int
    status: str = Field(min_length=1)