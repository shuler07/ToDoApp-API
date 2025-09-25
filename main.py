from fastapi import FastAPI, Response, Request, Depends, Cookie
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn
from sqlalchemy import select, update
from jose.exceptions import ExpiredSignatureError
from authx.exceptions import MissingTokenError
from contextlib import asynccontextmanager

from database import pg, sessionDep, rd
from auth import authentication
from models.usermodel import UserModel
from models.notesmodel import NotesModel
from schemas.userschema import UserCredsSchema, UserAuthSchema
from schemas.notesschema import CreateNoteSchema, ChangeNoteStatusSchema

# Setup lifespan for API and app


@asynccontextmanager
async def lifespan(app: FastAPI):
    await pg.create_all_tables()
    print("All tables created!")
    yield


app = FastAPI(lifespan=lifespan, version=0.2)

# Setup CORS middleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup limiter

limiter = Limiter(get_remote_address, ["5 per minute", "50 per hour"])
app.state.limiter = limiter

# Setup exceptions


def missing_token_error_handler(request: Request, exc: MissingTokenError):
    return JSONResponse("Refresh token not found", 401)


app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(MissingTokenError, missing_token_error_handler)

# Endpoints -> Authentication


@app.put("/authenticate_user", summary="Validate access token", tags=["Authentication"])
@limiter.shared_limit("30 per minute", "auth")
async def authenticate_user(userAuth: UserAuthSchema, request: Request):
    access_token = userAuth.access_token
    print("Checking access token:", access_token)

    if access_token is None:
        return JSONResponse("Access token not found", 401)

    try:
        payload = authentication.decode_token(access_token)
        print("Payload:", payload)

        uid = payload.get("sub")
        if uid is None:
            return JSONResponse("Invalid access token", 401)

        return {"isLoggedIn": True}
    except ExpiredSignatureError:
        print("Access token is expired")
        return {"isLoggedIn": False}


@app.put(
    "/refresh_user",
    summary="Create new access token from refresh token",
    tags=["Authentication"],
    dependencies=[Depends(authentication.auth.refresh_token_required)],
)
@limiter.shared_limit("30 per minute", "auth")
async def refresh_user(
    response: Response,
    request: Request,
    refresh_token: str = Cookie(
        None, alias=authentication.config.JWT_REFRESH_COOKIE_NAME
    ),
):
    print("Checking refresh token:", refresh_token)

    try:
        payload = authentication.decode_token(refresh_token)
        print("Payload:", payload)
        uid = payload.get("sub")

        if uid is None:
            return JSONResponse("Invalid refresh token", 401)

        new_access_token = authentication.auth.create_access_token(uid)
        new_refresh_token = authentication.auth.create_refresh_token(uid)
        response.set_cookie(
            authentication.config.JWT_REFRESH_COOKIE_NAME, new_refresh_token
        )

        return {"isLoggedIn": True, "access_token": new_access_token}
    except:
        print("Something went wrong [Refresh user]")
        return JSONResponse("Something went wrong", 500)


@app.post("/register", summary="Register", tags=["Authentication"])
@limiter.shared_limit("30 per minute", "auth")
async def register(
    creds: UserCredsSchema, response: Response, request: Request, session: sessionDep
):
    query = select(UserModel).where(UserModel.email == creds.email)
    result = await session.execute(query)
    user = result.scalar_one_or_none()

    if user is not None:
        return JSONResponse("User with such email already exists", 401)

    new_user = UserModel(email=creds.email, password=creds.password)
    session.add(new_user)
    await session.commit()

    query = select(UserModel.uid).where(UserModel.email == creds.email)
    result = await session.execute(query)
    uid = result.scalar_one_or_none()

    if uid is None:
        return JSONResponse("User not found", 401)

    access_token = authentication.auth.create_access_token(uid)
    refresh_token = authentication.auth.create_refresh_token(uid)
    response.set_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME, refresh_token)

    return {"isLoggedIn": True, "access_token": access_token}


@app.post("/login", summary="Login", tags=["Authentication"])
@limiter.shared_limit("30 per minute", "auth")
async def login(
    creds: UserCredsSchema, response: Response, request: Request, session: sessionDep
):
    query = select(UserModel).where(UserModel.email == creds.email)
    result = await session.execute(query)
    user = result.scalar_one_or_none()

    if user is None:
        return JSONResponse("Invalid email", 401)

    if user.password != creds.password:
        return JSONResponse("Invalid password", 401)

    uid = str(user.uid)

    access_token = authentication.auth.create_access_token(uid)
    refresh_token = authentication.auth.create_refresh_token(uid)
    response.set_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME, refresh_token)

    return {"isLoggedIn": True, "access_token": access_token}


@app.delete("/signout", summary="Sign out", tags=["Authentication"])
@limiter.shared_limit("30 per minute", "auth")
async def sign_out(
    userAuth: UserAuthSchema,
    response: Response,
    request: Request,
    refresh_token: str = Cookie(
        None, alias=authentication.config.JWT_REFRESH_COOKIE_NAME
    ),
):
    access_token = userAuth.access_token

    if access_token is None:
        return JSONResponse("Access token not found", 401)

    if refresh_token is None:
        return JSONResponse("Refresh token not found", 401)

    if not authentication.validate_token(access_token):
        return JSONResponse("Invalid access token", 401)
    
    if not authentication.validate_token(refresh_token):
        return JSONResponse('Invalid refresh token', 401)

    response.delete_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME)

    return {"isLoggedIn": False}


# Endpoints -> Notes


@app.post("/create_new_note", summary="Create new note", tags=["Notes"])
@limiter.shared_limit("20 per minute", "notes")
async def create_new_note(
    createNote: CreateNoteSchema, request: Request, session: sessionDep
):
    access_token = createNote.access_token
    if access_token is None:
        return JSONResponse("Access token not found", 401)

    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        return JSONResponse("Invalid access token", 401)

    try:
        new_note = NotesModel(
            uid=int(uid),
            title=createNote.title,
            text=createNote.text,
            status="not_completed",
        )
        session.add(new_note)
        await session.commit()
        return {"success": True}
    except:
        print("Something went wrong [Create new note]")
        return {"success": False}


@app.put("/get_notes", summary="Get notes", tags=["Notes"])
@limiter.shared_limit("20 per minute", "notes")
async def get_notes(userAuth: UserAuthSchema, request: Request, session: sessionDep):
    access_token = userAuth.access_token
    if access_token is None:
        return JSONResponse("Invalid access token", 401)

    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        return JSONResponse("Invalid access token", 401)

    try:
        query = select(NotesModel).where(NotesModel.uid == int(uid))
        result = await session.execute(query)
        notes = result.scalars().all()

        return notes
    except:
        print("Something went wrong [Get notes]")
        return JSONResponse("Something went wrong", 500)


@app.put("/change_note_status", summary="Change note status", tags=["Notes"])
@limiter.shared_limit("20 per minute", "notes")
async def change_note_status(
    changeNoteSchema: ChangeNoteStatusSchema, request: Request, session: sessionDep
):
    access_token = changeNoteSchema.access_token
    if access_token is None:
        return JSONResponse("Access token not found", 401)

    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        return JSONResponse("Invalid access token", 401)

    try:
        query = (
            update(NotesModel)
            .values(status=changeNoteSchema.status)
            .where(NotesModel.id == changeNoteSchema.id)
        )
        await session.execute(query)
        await session.commit()
        return {"success": True}
    except:
        print("Something went wrong [Change note status]")
        return {"success": False}


if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
