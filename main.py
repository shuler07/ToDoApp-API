from fastapi import FastAPI, Response, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select, update, delete
from jose.exceptions import ExpiredSignatureError
from authx.exceptions import MissingTokenError, JWTDecodeError
from contextlib import asynccontextmanager
from pwdlib import PasswordHash

from database import pg, sessionDep, rd
from auth import authentication
from smtp import email_sender
from models.usermodel import UserModel
from models.notesmodel import NotesModel
from schemas.userschema import UserCredsSchema
from schemas.notesschema import NoteIdSchema, CreateNoteSchema, NoteSchema


hasher_argon2 = PasswordHash.recommended()

# Create API app and setup it


@asynccontextmanager
async def lifespan(
    app: FastAPI,
):  # lifespan (before yield - on start, after yield - on exit)
    await pg.create_all_tables()
    print("All tables created!")
    yield


app = FastAPI(lifespan=lifespan, version="0.5")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)  # CORS middleware

limiter = Limiter(get_remote_address, ["5 per minute", "50 per hour"])  # Limiter
app.state.limiter = limiter


# Exceptions
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


# Endpoints (Authentication)


@app.get(
    "/authentication/validation/access_token",
    summary="Validate access token",
    tags=["Authentication"],
)
@limiter.shared_limit("30 per minute", "auth")
async def authenticate_user(
    request: Request, access_payload=Depends(authentication.auth.access_token_required)
):
    try:
        uid = access_payload.sub
        if uid is None:
            return JSONResponse("Invalid access token", 401)

        return {"isLoggedIn": True}
    except Exception as e:
        if issubclass(e.__class__, ExpiredSignatureError):
            print("Access token is expired")
        else:
            print("Something went wrong [Authenticate user]", e)

        return {"isLoggedIn": False}


@app.get(
    "/authentication/validation/refresh_token",
    summary="Create new access token from refresh token",
    tags=["Authentication"],
)
@limiter.shared_limit("30 per minute", "auth")
async def refresh_user(
    response: Response,
    request: Request,
    refresh_payload=Depends(authentication.auth.refresh_token_required),
):
    try:
        uid = refresh_payload.sub

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
        if issubclass(e.__class__, ExpiredSignatureError):
            print("Refresh token is expired")
        else:
            print("Something went wrong [Refresh user]", e)

        return JSONResponse("Something went wrong", 500)


@app.post("/authentication/register", summary="Register user", tags=["Authentication"])
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

        hashed_password = hasher_argon2.hash(creds.password)
        sub = f'{creds.email} {hashed_password}'
        access_token = authentication.auth.create_access_token(sub)

        email_link = f"http://localhost:8000/authentication/verification/{access_token}"
        email_msg = f"Subject: Verify your email for ToDoApp\n\n\
Follow the link to verify your email: {email_link}\n\
(If you didnt registered on this service, just ignore the message)"

        email_sender.send_message(creds.email, email_msg)

        return {"isRegistered": True}
    except Exception as e:
        print("Something went wrong [Register]", e)

        return {"isRegistered": False}


@app.post("/authentication/login", summary="Login user", tags=["Authentication"])
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

        if not hasher_argon2.verify(creds.password, user.password):
            return JSONResponse("Invalid password", 401)

        uid = str(user.uid)

        access_token = authentication.auth.create_access_token(uid)
        refresh_token = authentication.auth.create_refresh_token(uid)
        response.set_cookie(authentication.config.JWT_ACCESS_COOKIE_NAME, access_token)
        response.set_cookie(
            authentication.config.JWT_REFRESH_COOKIE_NAME, refresh_token
        )

        return {"isLoggedIn": True}
    except Exception as e:
        print("Something went wrong [Login]", e)

        return {"isLoggedIn": False}


@app.get("/authentication/verification/{access_token}", summary='Verify email', tags=['Authentication'])
@limiter.shared_limit("30 per minute", "auth")
async def verify(access_token: str, request: Request, response: Response, session: sessionDep):
    data = authentication.decode_token(access_token)
    if not data['success']:
        return {data.message}
    
    email, hashed_password = data['data'].split()

    try:
        user = UserModel(
            email=email,
            password=hashed_password
        )
        session.add(user)
        await session.commit()

        return {'Successfully registered! You can back to site and login into your account'}
    except Exception as e:
        print('Something went wrong [Verify]', e)

        return {'Something went wrong, try again later'}


@app.delete(
    "/authentication/signout",
    summary="Sign out user",
    tags=["Authentication"],
    dependencies=[
        Depends(authentication.auth.access_token_required),
        Depends(authentication.auth.refresh_token_required),
    ],
)
@limiter.shared_limit("30 per minute", "auth")
async def sign_out(response: Response, request: Request):
    response.delete_cookie(authentication.config.JWT_ACCESS_COOKIE_NAME)
    response.delete_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME)

    return {"isLoggedIn": False}


# Endpoints (Notes)


@app.post("/notes", summary="Create new note", tags=["Notes"])
@limiter.shared_limit("30 per minute", "notes")
async def create_new_note(
    createNote: CreateNoteSchema,
    request: Request,
    session: sessionDep,
    access_payload=Depends(authentication.auth.access_token_required),
):
    uid = access_payload.sub
    try:
        new_note = NotesModel(
            uid=int(uid),
            title=createNote.title,
            text=createNote.text,
            status="not_completed",
            tags=createNote.tags,
        )
        session.add(new_note)
        await session.commit()
        await session.refresh(new_note)

        return {"success": True, "note": new_note}
    except Exception as e:
        print("Something went wrong [Create new note]", e)

        return {"success": False}


@app.get("/notes", summary="Get notes", tags=["Notes"])
@limiter.shared_limit("30 per minute", "notes")
async def get_notes(
    request: Request,
    session: sessionDep,
    access_payload=Depends(authentication.auth.access_token_required),
):
    uid = access_payload.sub
    try:
        query = select(NotesModel).where(NotesModel.uid == int(uid))
        result = await session.execute(query)
        notes = result.scalars().all()

        return notes
    except Exception as e:
        print("Something went wrong [Get notes]", e)

        return JSONResponse("Something went wrong", 500)


@app.put(
    "/notes",
    summary="Update note",
    tags=["Notes"],
    dependencies=[Depends(authentication.auth.access_token_required)],
)
@limiter.shared_limit("30 per minute", "notes")
async def update_note(noteSchema: NoteSchema, request: Request, session: sessionDep):
    try:
        query = (
            update(NotesModel)
            .values(
                title=noteSchema.title,
                text=noteSchema.text,
                tags=noteSchema.tags,
                status=noteSchema.status,
            )
            .where(NotesModel.id == noteSchema.id)
        )
        await session.execute(query)
        await session.commit()

        return {"success": True}
    except Exception as e:
        print("Something went wrong [Update note]", e)

        return {"success": False}


@app.delete(
    "/notes",
    summary="Delete note",
    tags=["Notes"],
    dependencies=[Depends(authentication.auth.access_token_required)],
)
@limiter.shared_limit("30 per minute", "notes")
async def delete_note(
    noteIdSchema: NoteIdSchema, session: sessionDep, request: Request
):
    try:
        query = delete(NotesModel).where(NotesModel.id == noteIdSchema.id)
        await session.execute(query)
        await session.commit()

        return {"success": True}
    except Exception as e:
        print("Something went wrong [Delete note]", e)

        return {"success": False}
