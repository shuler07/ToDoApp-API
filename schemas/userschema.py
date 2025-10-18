from pydantic import BaseModel, Field, EmailStr

class UserCredsSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)

class UserUsernameSchema(BaseModel):
    username: str = Field(min_length=4)

class UserSchema(UserCredsSchema, UserUsernameSchema):
    pass