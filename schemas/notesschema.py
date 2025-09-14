from pydantic import BaseModel, Field

class CreateNoteSchema(BaseModel):
    access_token: str
    title: str = Field(min_length=1)
    text: str = Field(min_length=1)