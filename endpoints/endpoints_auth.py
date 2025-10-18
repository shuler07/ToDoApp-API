from fastapi import Request, Response, Depends, APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import select, update
from pwdlib import PasswordHash

from limiter import limiter
from auth import authentication
from smtp import email_sender
from database import sessionDep
from models.usermodel import UserModel
from schemas.userschema import UserSchema, UserCredsSchema, UserUsernameSchema
from constants import LIMIT_VALUE_AUTH, SCOPE_AUTH

router_auth = APIRouter(prefix="/auth", tags=["Authentication"])
hasher = PasswordHash.recommended()


@router_auth.get(
    "/validation/access_token",
    description="Accepts access token from cookie. Returns True if access token is fresh and valid, False otherwise",
    summary="Validate access token",
)
@limiter.shared_limit(LIMIT_VALUE_AUTH, SCOPE_AUTH)
async def authenticate_user(
    request: Request, access_payload=Depends(authentication.auth.access_token_required)
):
    try:
        uid = access_payload.sub
        if uid is None:
            return JSONResponse("Invalid access token", 401)

        return {"isLoggedIn": True}
    except Exception as e:
        print("Something went wrong [Authenticate user]", e)

        return {"isLoggedIn": False}


@router_auth.get(
    "/validation/refresh_token",
    description="Accepts refresh token from cookie. Returns True and sends access and refresh tokens into cookie if refresh token is fresh and valid, False otherwise",
    summary="Create new access token from refresh token",
)
@limiter.shared_limit(LIMIT_VALUE_AUTH, SCOPE_AUTH)
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
        print("Something went wrong [Refresh user]", e)

        return JSONResponse("Something went wrong", 500)


@router_auth.post(
    "/register",
    description="Accepts user object. Returns True and sends verification email if creds are valid and user doesnt exist, False otherwise",
    summary="Register user",
)
@limiter.shared_limit(LIMIT_VALUE_AUTH, SCOPE_AUTH)
async def register(
    newUser: UserSchema, request: Request, session: sessionDep
):
    try:
        query = select(UserModel).where(UserModel.email == newUser.email)
        result = await session.execute(query)
        user = result.scalar_one_or_none()

        if user is not None:
            return {'isRegistered': False, 'error': 'exists'}

        hashed_password = hasher.hash(newUser.password)
        sub = f"{newUser.email} {hashed_password} {newUser.username}"
        access_token = authentication.auth.create_access_token(sub)

        email_link = f"http://localhost:8000/auth/verification/{access_token}"
        email_msg = f"Subject: Verify your email for ToDoApp\n\n\
Follow the link to verify your email: {email_link}\n\
(If you didnt registered on this service, just ignore the message)"

        email_sender.send_message(newUser.email, email_msg)

        return {"isRegistered": True}
    except Exception as e:
        print("Something went wrong [Register]", e)

        return {"isRegistered": False, 'error': 'unknown'}


@router_auth.post(
    "/login",
    description="Accepts creds object. Returns True and sends access and refresh tokens into cookie if creds valid, False otherwise",
    summary="Login user",
)
@limiter.shared_limit(LIMIT_VALUE_AUTH, SCOPE_AUTH)
async def login(
    creds: UserCredsSchema, response: Response, request: Request, session: sessionDep
):
    try:
        query = select(UserModel).where(UserModel.email == creds.email)
        result = await session.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            return {'isLoggedIn': False}

        if not hasher.verify(creds.password, user.password):
            return {'isLoggedIn': False}

        uid = str(user.uid)

        access_token = authentication.auth.create_access_token(uid)
        refresh_token = authentication.auth.create_refresh_token(uid)
        response.set_cookie(authentication.config.JWT_ACCESS_COOKIE_NAME, access_token)
        response.set_cookie(
            authentication.config.JWT_REFRESH_COOKIE_NAME, refresh_token
        )

        return {"isLoggedIn": True, "username": user.username}
    except Exception as e:
        print("Something went wrong [Login]", e)

        return {"isLoggedIn": False}


@router_auth.get(
    "/verification/{access_token}",
    description="Accepts access token from url. Creates new user with email and password from token",
    summary="Verify email",
)
@limiter.shared_limit(LIMIT_VALUE_AUTH, SCOPE_AUTH)
async def verify(
    access_token: str, request: Request, session: sessionDep
):
    data = authentication.decode_token(access_token)
    if not data["success"]:
        return {data.message}

    email, hashed_password, username = data["data"].split()

    try:
        user = UserModel(email=email, password=hashed_password, username=username)
        session.add(user)
        await session.commit()

        return {
            "Successfully registered! You can back to site and login into your account"
        }
    except Exception as e:
        print("Something went wrong [Verify]", e)

        return {"Something went wrong, try again later"}


@router_auth.put(
    "/user/username",
    description="Accepts username and access token from cookie. Returns True if username correct and access token valid, False otherwise",
    summary="Update user's username",
)
@limiter.shared_limit(LIMIT_VALUE_AUTH, SCOPE_AUTH)
async def update_username(
    userUsernameSchema: UserUsernameSchema,
    request: Request,
    session: sessionDep,
    access_payload=Depends(authentication.auth.access_token_required),
):
    uid = int(access_payload.sub)
    username = userUsernameSchema.username
    try:
        query = update(UserModel).values(username=username).where(UserModel.uid == uid)
        await session.execute(query)
        await session.commit()

        return {"success": True}
    except Exception as e:
        print("Something went wrong [Update username]", e)

        return {"success": False}


@router_auth.get(
    "/username",
    description="Accepts access token from cookie. Returns True and username if access token valid, False otherwise",
    summary="Get username by uid",
)
@limiter.shared_limit(LIMIT_VALUE_AUTH, SCOPE_AUTH)
async def get_username(
    request: Request,
    session: sessionDep,
    access_payload=Depends(authentication.auth.access_token_required),
):
    uid = int(access_payload.sub)
    try:
        query = select(UserModel.username).where(UserModel.uid == uid)
        result = await session.execute(query)
        username = result.scalar_one_or_none()

        if username is None:
            return {"success": False}

        return {"success": True, "username": username}
    except Exception as e:
        print("Something went wrong [Get username]", e)
        return {"success": False}


@router_auth.delete(
    "/signout",
    description="Accepts access and refresh tokens from cookie. Returns True and removes access and refresh tokens from cookie if access and refresh tokens are fresh and valid, False otherwise",
    summary="Sign out user",
    dependencies=[
        Depends(authentication.auth.access_token_required),
        Depends(authentication.auth.refresh_token_required),
    ],
)
@limiter.shared_limit(LIMIT_VALUE_AUTH, SCOPE_AUTH)
async def sign_out(response: Response, request: Request):
    response.delete_cookie(authentication.config.JWT_ACCESS_COOKIE_NAME)
    response.delete_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME)

    return {"isLoggedIn": False}
