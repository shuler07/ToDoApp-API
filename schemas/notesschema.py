from pydantic import BaseModel

class CreateNoteSchema(BaseModel):
    access_token: str
    note_text: str