from fastapi import FastAPI, Response, Request, Depends, Cookie
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select, update, delete
from jose.exceptions import ExpiredSignatureError
from authx.exceptions import MissingTokenError, JWTDecodeError
from contextlib import asynccontextmanager

from database import pg, sessionDep, rd
from auth import authentication
from models.usermodel import UserModel
from models.notesmodel import NotesModel
from schemas.userschema import UserCredsSchema
from schemas.notesschema import NoteIdSchema, CreateNoteSchema, NoteSchema

# Setup lifespan for API and app


@asynccontextmanager
async def lifespan(app: FastAPI):
    await pg.create_all_tables()
    print("All tables created!")
    yield


app = FastAPI(lifespan=lifespan, version="0.3")

# Setup CORS middleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=['https://shuler07.github.io'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup limiter

limiter = Limiter(get_remote_address, ["5 per minute", "50 per hour"])
app.state.limiter = limiter

# Setup exceptions


def missing_token_error_handler(request: Request, exc: MissingTokenError):
    if "access" in str(exc):
        return JSONResponse("Access token not found", 401)
    else:
        return JSONResponse("Refresh token not found", 401)


def jwt_decode_token_error_handler(request: Request, exc: JWTDecodeError):
    return JSONResponse("Token decode error", 401)


app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(MissingTokenError, missing_token_error_handler)
app.add_exception_handler(JWTDecodeError, jwt_decode_token_error_handler)

# Endpoints -> Authentication


@app.get(
    "/authenticate_user",
    summary="Validate access token",
    tags=["Authentication"],
    dependencies=[Depends(authentication.auth.access_token_required)],
)
@limiter.shared_limit("30 per minute", "auth")
async def authenticate_user(
    request: Request,
    access_token: str = Cookie(
        None, alias=authentication.config.JWT_ACCESS_COOKIE_NAME
    ),
):
    print("Checking access token:", access_token)

    try:
        payload = authentication.decode_token(access_token)
        print("Payload:", payload)

        uid = payload.get("sub")
        if uid is None:
            return JSONResponse("Invalid access token", 401)

        return {"isLoggedIn": True}
    except Exception as e:
        if issubclass(e, ExpiredSignatureError):
            print("Access token is expired")
        else:
            print('Something went wrong [Authenticate user]', e)
        return {"isLoggedIn": False}


@app.get(
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
            authentication.config.JWT_ACCESS_COOKIE_NAME, new_access_token
        )
        response.set_cookie(
            authentication.config.JWT_REFRESH_COOKIE_NAME, new_refresh_token
        )

        return {"isLoggedIn": True}
    except Exception as e:
        if issubclass(e, ExpiredSignatureError):
            print('Refresh token is expired')
        else:
            print("Something went wrong [Refresh user]", e)
        return JSONResponse("Something went wrong", 500)


@app.post("/register", summary="Register", tags=["Authentication"])
@limiter.shared_limit("30 per minute", "auth")
async def register(
    creds: UserCredsSchema, response: Response, request: Request, session: sessionDep
):
    try:
        query = select(UserModel).where(UserModel.email == creds.email)
        result = await session.execute(query)
        user = result.scalar_one_or_none()

        if user is not None:
            return JSONResponse("User with such email already exists", 401)

        new_user = UserModel(email=creds.email, password=creds.password)
        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)

        uid = str(new_user.uid)

        access_token = authentication.auth.create_access_token(uid)
        refresh_token = authentication.auth.create_refresh_token(uid)
        response.set_cookie(authentication.config.JWT_ACCESS_COOKIE_NAME, access_token)
        response.set_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME, refresh_token)

        return {"isLoggedIn": True}
    except Exception as e:
        print('Something went wrong [Register]', e)
        return {'isLoggedIn': False}


@app.post("/login", summary="Login", tags=["Authentication"])
@limiter.shared_limit("30 per minute", "auth")
async def login(
    creds: UserCredsSchema, response: Response, request: Request, session: sessionDep
):
    try:
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
        response.set_cookie(authentication.config.JWT_ACCESS_COOKIE_NAME, access_token)
        response.set_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME, refresh_token)

        return {"isLoggedIn": True}
    except Exception as e:
        print('Something went wrong [Login]', e)
        return {'isLoggedIn': False}


@app.delete(
    "/signout",
    summary="Sign out",
    tags=["Authentication"],
    dependencies=[
        Depends(authentication.auth.access_token_required),
        Depends(authentication.auth.refresh_token_required),
    ],
)
@limiter.shared_limit("30 per minute", "auth")
async def sign_out(
    response: Response,
    request: Request,
    access_token: str = Cookie(
        None, alias=authentication.config.JWT_ACCESS_COOKIE_NAME
    ),
    refresh_token: str = Cookie(
        None, alias=authentication.config.JWT_REFRESH_COOKIE_NAME
    ),
):
    if not authentication.validate_token(access_token):
        return JSONResponse("Invalid access token", 401)

    if not authentication.validate_token(refresh_token):
        return JSONResponse("Invalid refresh token", 401)

    response.delete_cookie(authentication.config.JWT_ACCESS_COOKIE_NAME)
    response.delete_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME)

    return {"isLoggedIn": False}


# Endpoints -> Notes


@app.post(
    "/create_new_note",
    summary="Create new note",
    tags=["Notes"],
    dependencies=[Depends(authentication.auth.access_token_required)],
)
@limiter.shared_limit("30 per minute", "notes")
async def create_new_note(
    createNote: CreateNoteSchema,
    request: Request,
    session: sessionDep,
    access_token: str = Cookie(
        None, alias=authentication.config.JWT_ACCESS_COOKIE_NAME
    ),
):
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
        await session.refresh(new_note)
        
        return {'success': True, 'note': new_note}
    except Exception as e:
        print("Something went wrong [Create new note, Creating note]", e)
        return {"success": False}


@app.get(
    "/get_notes",
    summary="Get notes",
    tags=["Notes"],
    dependencies=[Depends(authentication.auth.access_token_required)],
)
@limiter.shared_limit("30 per minute", "notes")
async def get_notes(
    request: Request,
    session: sessionDep,
    access_token: str = Cookie(
        None, alias=authentication.config.JWT_ACCESS_COOKIE_NAME
    ),
):
    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        return JSONResponse("Invalid access token", 401)

    try:
        query = select(NotesModel).where(NotesModel.uid == int(uid))
        result = await session.execute(query)
        notes = result.scalars().all()

        return notes
    except Exception as e:
        print("Something went wrong [Get notes]", e)
        return JSONResponse("Something went wrong", 500)


@app.put(
    "/update_note",
    summary="Update note",
    tags=["Notes"],
    dependencies=[Depends(authentication.auth.access_token_required)],
)
@limiter.shared_limit("30 per minute", "notes")
async def update_note(
    noteSchema: NoteSchema,
    request: Request,
    session: sessionDep,
    access_token: str = Cookie(
        None, alias=authentication.config.JWT_ACCESS_COOKIE_NAME
    ),
):
    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        return JSONResponse("Invalid access token", 401)

    try:
        query = (
            update(NotesModel)
            .values(title=noteSchema.title, text=noteSchema.text, tags=noteSchema.tags, status=noteSchema.status)
            .where(NotesModel.id == noteSchema.id)
        )
        await session.execute(query)
        await session.commit()
        return {"success": True}
    except Exception as e:
        print("Something went wrong [Update note]", e)
        return {"success": False}


@app.delete(
    "/delete_note",
    summary="Delete note",
    tags=["Notes"],
    dependencies=[Depends(authentication.auth.access_token_required)],
)
@limiter.shared_limit("30 per minute", "notes")
async def delete_note(
    noteIdSchema: NoteIdSchema,
    session: sessionDep,
    request: Request,
    access_token: str = Cookie(alias=authentication.config.JWT_ACCESS_COOKIE_NAME),
):
    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        return JSONResponse('Invalid access token', 401)
    
    try:
        query = delete(NotesModel).where(NotesModel.id == noteIdSchema.id)
        await session.execute(query)
        await session.commit()

        return {'success': True}
    except Exception as e:
        print('Something went wrong [Delete note]', e)
        return {'success': False}
