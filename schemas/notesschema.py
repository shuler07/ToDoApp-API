from pydantic import BaseModel, Field

class CreateNoteSchema(BaseModel):
    title: str = Field(min_length=1)
    text: str = Field(min_length=1)

class ChangeNoteStatusSchema(BaseModel):
    id: int
    status: str = Field(min_length=1)