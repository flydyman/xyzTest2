from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
import string

from datetime import datetime, timedelta

from passlib.context import CryptContext
from sqlalchemy import create_engine, Table, Column, Integer, String, Boolean, MetaData, insert, select
from jose import JWTError, jwt
import base64
import itertools

SECRET_KEY = "92eba8e035b6087bf9842a9e06a3c16e09384e9128b2f63d04423cdc5e4a6805"
ALGORITHM = "HS256"
TOKEN_EXPIRATION = 30

INNER_SHIFT = 5

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_pass(source: str):
    return pwd_context.hash(source)


def verify_pass(plain, hashed):
    return pwd_context.verify(plain, hashed)


app = FastAPI()
oauth_scheme = OAuth2PasswordBearer(tokenUrl='token')

db_engine = create_engine("sqlite+pysqlite:///:memory:", echo=True, future=True)

metadata_obj = MetaData()
user_table = Table(
    "user",
    metadata_obj,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('username', String(30), unique=True),
    Column('password', String(255)),
    Column('is_blocked', Boolean, default=False)
)

metadata_obj.create_all(db_engine)

test1 = insert(user_table).values(username='test1', password=hash_pass('test1'))
test2 = insert(user_table).values(username='test2', password=hash_pass('test2test2'), is_blocked=True)

with db_engine.connect() as conn:
    conn.execute(test1)
    conn.execute(test2)

    conn.commit()


class User(BaseModel):
    id: int
    username: str
    is_blocked: bool


class UserData(User):
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


def get_user(username: str):
    user_query = select(user_table).where(user_table.c.username == username)
    with db_engine.connect() as conn:
        res = conn.execute(user_query)
    rows = [r for r in res]
    row = rows[0]
    user = UserData(id=row['id'], username=row['username'], is_blocked=row['is_blocked'], password=row['password'])
    return user


async def get_curr_user(token: str = Depends(oauth_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_data = TokenData(username=username)
        user = get_user(username=token_data.username)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Wrong token!'
        )
    if not user or user.is_blocked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='User not found or blocked'
        )
    clean_user = User(
        id=user.id,
        username=user.username,
        is_blocked=user.is_blocked
    )
    return clean_user


async def get_current_active_user(current_user: User = Depends(get_curr_user)):
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Inactive user'
        )
    return current_user


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_pass(password, user.password):
        return False
    return user


def create_access_token(data: dict, expiration_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expiration_delta:
        expire = datetime.utcnow() + expiration_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='User not found or wrong username/password'
        )
    elif user.is_blocked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='User is blocked'
        )
    access_token_expiration = timedelta(minutes=TOKEN_EXPIRATION)
    access_token = create_access_token(data={"sub": user.username}, expiration_delta=access_token_expiration)
    return {"access_token": access_token, "token_type": "Bearer"}


def xor_cipher(source, encode = True):
    if not encode:
        source = base64.b64decode(source.encode()).decode()
    res = ''.join(chr(ord(i) ^ ord(j)) for (i, j) in zip(source, itertools.cycle(string.printable)))
    if encode:
        return base64.b64encode(res.encode()).strip()
    return res.strip()


@app.get("/encode/")
async def encode(source: str = None):
    if not source:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Parameter "source" is not set'
        )
    return xor_cipher(source)


@app.get("/decode/")
async def decode(source: str = None):
    if not source:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Parameter "source" is not set'
        )
    return xor_cipher(source, False)

