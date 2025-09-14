from fastapi import FastAPI, HTTPException, Response, Depends, Cookie
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from sqlalchemy import select

from jose import exceptions

from database import sessionDep
from auth import authentication
from models.usermodel import UserModel
from models.notesmodel import NotesModel
from schemas.userschema import UserCredsSchema, UserAuthSchema
from schemas.notesschema import CreateNoteSchema

app = FastAPI()

# Setup middleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:5173'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

# Endpoints -> Authentication

@app.post('/me', summary='Check access token', tags=['Authentication'])
def get_auth_data(userAuth: UserAuthSchema):
    access_token = userAuth.access_token
    print('Checking token:', access_token)
    
    if access_token is None:
        return {'isLoggedIn': False}
    
    try:
        payload = authentication.decode_token(access_token)
        print('Payload:', payload)
        uid = payload.get('sub')
        if uid is None:
            return {'isLoggedIn': False, 'isRefresh': True}
        return {'isLoggedIn': True, 'uid': uid}
    except exceptions.ExpiredSignatureError:
        print('Token is expired')
        return {'isLoggedIn': False, 'isRefresh': True}

@app.post('/refresh', summary='Refresh token', tags=['Authentication'], dependencies=[Depends(authentication.auth.refresh_token_required)])
def refresh_token(response: Response, refresh_token: str = Cookie(None, alias=authentication.config.JWT_REFRESH_COOKIE_NAME)):
    print('Refreshing token', refresh_token)
    try:
        payload = authentication.decode_token(refresh_token)
        print('payload:', payload)
        new_access_token = authentication.auth.create_access_token(payload.get('sub'))
        new_refresh_token = authentication.auth.create_refresh_token(payload.get('sub'))
        response.set_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME, new_refresh_token)
        return {'isLoggedIn': True, 'access_token': new_access_token}
    except:
        print('Sonething went wrong')
        return {'isLoggedIn': False}

@app.post('/register', summary='Register', tags=['Authentication'])
def register(creds: UserCredsSchema, response: Response, session: sessionDep):
    query = select(UserModel).where(UserModel.email == creds.email)
    result = session.execute(query)
    user = result.scalar_one_or_none()

    if user != None:
        raise HTTPException(401, 'User with such email already existing')
    
    new_user = UserModel(
        email=creds.email,
        password=creds.password
    )
    session.add(new_user)
    session.commit()

    query = select(UserModel.uid).where(UserModel.email == creds.email)
    result = session.execute(query)
    uid = result.scalar_one_or_none()

    if uid == None:
        raise HTTPException(404, 'User not found')
    
    access_token = authentication.auth.create_access_token(uid=uid)
    refresh_token = authentication.auth.create_refresh_token(uid=uid)
    response.set_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME, refresh_token)
    return {'isLoggedIn': True, 'access_token': access_token, 'uid': uid}

@app.post('/login', summary='Login', tags=['Authentication'])
def login(creds: UserCredsSchema, response: Response, session: sessionDep):
    query = select(UserModel).where(UserModel.email == creds.email)
    result = session.execute(query)
    user = result.scalar_one_or_none()

    if user == None: 
        raise HTTPException(401, 'Invalid email')
    if user.password != creds.password:
        raise HTTPException(401, 'Invalid password')
        
    access_token = authentication.auth.create_access_token(uid=str(user.uid))
    refresh_token = authentication.auth.create_refresh_token(uid=str(user.uid))
    response.set_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME, refresh_token)
    return {'isLoggedIn': True, 'access_token': access_token, 'uid': user.uid}
        
@app.post('/signout', summary='Sign out', tags=['Authentication'])
def sign_out(userAuth: UserAuthSchema, response: Response, refresh_token: str = Cookie(None, alias=authentication.config.JWT_REFRESH_COOKIE_NAME)):
    access_token = userAuth.access_token
    if access_token is None or refresh_token is None:
        raise HTTPException(401, 'User not logged in')
    if not authentication.validate_token(access_token):
        return
    
    response.delete_cookie(authentication.config.JWT_REFRESH_COOKIE_NAME)
    return {'isLoggedIn': False}

# Endpoints -> Notes

@app.post('/create_new_note', summary='Create new note', tags=['Notes'])
def create_new_note(createNote: CreateNoteSchema, session: sessionDep):
    access_token = createNote.access_token
    if access_token is None:
        raise HTTPException(401, 'User not logged in')
    
    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        raise HTTPException(401, 'Invalid token')
    
    new_note = NotesModel(
        uid=int(uid),
        title=createNote.title,
        text=createNote.text,
        status='not_completed'
    )
    session.add(new_note)
    session.commit()

    return {'success': True}

@app.post('/get_notes', summary='Get notes', tags=['Notes'])
def get_notes(userAuth: UserAuthSchema, session: sessionDep):
    access_token = userAuth.access_token
    if access_token is None:
        raise HTTPException(401, 'User not logged in')
    
    uid = authentication.get_uid_from_token(access_token)
    if uid is None:
        raise HTTPException(401, 'Invalid token')
    
    query = select(NotesModel).where(NotesModel.uid == int(uid))
    result = session.execute(query)
    notes = result.scalars().all()
    print('Notes count:', len(notes))
    return notes

if __name__ == '__main__':
    uvicorn.run('main:app', reload=True)