from pydantic import BaseModel, Field, EmailStr

class UserCredsSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)

class UserAuthSchema(BaseModel):
    access_token: str