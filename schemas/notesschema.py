from pydantic import BaseModel, Field

class NoteIdSchema(BaseModel):
    id: int

class CreateNoteSchema(BaseModel):
    title: str = Field(min_length=1)
    text: str = Field(min_length=1)

class ChangeNoteStatusSchema(NoteIdSchema):
    status: str = Field(min_length=1)