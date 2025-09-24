from fastapi import FastAPI, HTTPException, Response, Request, Depends, Cookie
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn
from sqlalchemy import select, update
from jose import exceptions
from contextlib import asynccontextmanager

from database import db, sessionDep
from auth import authentication
from models.usermodel import UserModel
from models.notesmodel import NotesModel
from schemas.userschema import UserCredsSchema, UserAuthSchema
from schemas.notesschema import CreateNoteSchema, ChangeNoteStatusSchema

# Setup lifespan for API and app

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.create_all_tables()
    print('All tables created!')
    yield

app = FastAPI(lifespan=lifespan)

# Setup CORS middleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:5173'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

# Setup limiter

limiter = Limiter(get_remote_address, ['5 per minute', '50 per hour'])

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Endpoints -> Authentication

@app.put('/authenticate_user', summary='Validate access token', tags=['Authentication'])
@limiter.shared_limit('10 per minute', 'auth')
def authenticate_user(userAuth: UserAuthSchema, request: Request):
    access_token = userAuth.access_token
    print('Checking access token:', access_token)
    
    if access_token is None:
        raise HTTPException(401, 'Access token not found')
    
    try:
        payload = authentication.decode_token(access_token)
        print('Payload:', payload)

        uid = payload.get('sub')
        if uid is None:
            raise HTTPException(401, 'Invalid access token')
        
        return {'isLoggedIn': True}
    except exceptions.ExpiredSignatureError:
        print('Access token is expired')
        return {'isLoggedIn': False}

@app.put('/refresh_user', summary='Create new access token from refresh token', tags=['Authentication'], dependencies=[Depends(authentication.auth.refresh_token_required)])
@limiter.shared_limit('10 per minute', 'auth')
def refresh_user(response: Response, request: Request, refresh_token: str = Cookie(None, alias=authentication.config.JWT_REFRESH_COOKIE_NAME)):
    print('Checking refresh token:', refresh_token)

    try:
        payload = authentication.decode_token(refresh_token)
        print('Payload:', payload)
        uid = payload.get('sub')

        if uid is None:
            raise HTTPException(401, 'Invalid refresh token')

        new_access_token = authentication.auth.create_access_token(uid)
        new_refresh_token = authentication.auth.create_refresh_token(uid)
        response.set_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME, new_refresh_token)

        return {'isLoggedIn': True, 'access_token': new_access_token}
    except:
        print('Something went wrong')
        raise HTTPException(500, 'Something went wrong')

@app.post('/register', summary='Register', tags=['Authentication'])
@limiter.shared_limit('10 per minute', 'auth')
async def register(creds: UserCredsSchema, response: Response, session: sessionDep):
    query = select(UserModel).where(UserModel.email == creds.email)
    result = await session.execute(query)
    user = result.scalar_one_or_none()

    if user is not None:
        raise HTTPException(401, 'User with such email already existing')
    
    new_user = UserModel(
        email=creds.email,
        password=creds.password
    )
    session.add(new_user)
    await session.commit()

    query = select(UserModel.uid).where(UserModel.email == creds.email)
    result = await session.execute(query)
    uid = result.scalar_one_or_none()

    if uid is None:
        raise HTTPException(401, 'User not found')
    
    access_token = authentication.auth.create_access_token(uid)
    refresh_token = authentication.auth.create_refresh_token(uid)
    response.set_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME, refresh_token)

    return {'isLoggedIn': True, 'access_token': access_token}

@app.post('/login', summary='Login', tags=['Authentication'])
@limiter.shared_limit('10 per minute', 'auth')
async def login(creds: UserCredsSchema, response: Response, session: sessionDep):
    query = select(UserModel).where(UserModel.email == creds.email)
    result = await session.execute(query)
    user = result.scalar_one_or_none()

    if user is None: 
        raise HTTPException(401, 'Invalid email')
    
    if user.password != creds.password:
        raise HTTPException(401, 'Invalid password')
    
    uid = str(user.uid)
        
    access_token = authentication.auth.create_access_token(uid)
    refresh_token = authentication.auth.create_refresh_token(uid)
    response.set_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME, refresh_token)
    
    return {'isLoggedIn': True, 'access_token': access_token}
        
@app.delete('/signout', summary='Sign out', tags=['Authentication'])
@limiter.shared_limit('10 per minute', 'auth')
def sign_out(userAuth: UserAuthSchema, response: Response, refresh_token: str = Cookie(None, alias=authentication.config.JWT_REFRESH_COOKIE_NAME)):
    access_token = userAuth.access_token

    if access_token is None:
        raise HTTPException(401, 'Access token not found')
    
    if refresh_token is None:
        raise HTTPException(401, 'Refresh token not found')
    
    if not authentication.validate_token(access_token):
        raise HTTPException(401, 'Invalid access token')
    
    response.delete_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME)

    return {'isLoggedIn': False}

# Endpoints -> Notes

@app.post('/create_new_note', summary='Create new note', tags=['Notes'])
@limiter.shared_limit('15 per minute', 'notes')
async def create_new_note(createNote: CreateNoteSchema, session: sessionDep):
    access_token = createNote.access_token
    if access_token is None:
        raise HTTPException(401, 'Access token not found')
    
    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        raise HTTPException(401, 'Invalid access token')
    
    try:
        new_note = NotesModel(
            uid=int(uid),
            title=createNote.title,
            text=createNote.text,
            status='not_completed'
        )
        session.add(new_note)
        await session.commit()
        return {'success': True}
    except:
        print('Something went wrong [Create new note]')
        return {'success': False}

@app.put('/get_notes', summary='Get notes', tags=['Notes'])
@limiter.shared_limit('15 per minute', 'notes')
async def get_notes(userAuth: UserAuthSchema, session: sessionDep):
    access_token = userAuth.access_token
    if access_token is None:
        raise HTTPException(401, 'Invalid access token')
    
    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        raise HTTPException(401, 'Invalid access token')
    
    try:
        query = select(NotesModel).where(NotesModel.uid == int(uid))
        result = await session.execute(query)
        notes = result.scalars().all()
        return notes
    except:
        print('Something went wrong [Get notes]')
        raise HTTPException(500, 'Something went wrong')

@app.put('/change_note_status', summary='Change note status', tags=['Notes'])
@limiter.shared_limit('15 per minute', 'notes')
async def change_note_status(changeNoteSchema: ChangeNoteStatusSchema, session: sessionDep):
    access_token = changeNoteSchema.access_token
    if access_token is None:
        raise HTTPException(401, 'Access token not found')
    
    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        raise HTTPException(401, 'Invalid access token')
    
    try:    
        query = update(NotesModel).values(status=changeNoteSchema.status).where(NotesModel.id == changeNoteSchema.id)
        await session.execute(query)
        await session.commit()
        return {'success': True}
    except:
        print('Something went wrong [Change note status]')
        return {'success': False}



if __name__ == '__main__':
    uvicorn.run('main:app', reload=True)