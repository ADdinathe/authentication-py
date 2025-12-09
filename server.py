from typing import Optional
import base64
import hmac
import hashlib
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response
import json

app = FastAPI()
SECRET_KEY = "94246ce346bbe6fb3db96c8176e76268a8642be5842ee76ba6b762253504c385"
PASSWORD_SALT = "7ae1f2eddbded97086a41fcb2cd0255dd832efbaee0bfb1c73d0cd5964a45b21"


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"]
    return password_hash == stored_password_hash


users = {
    'anton@gmail.com': {
        "name": 'Антон',
        # 1234567890
        "password": '94246ce346bbe6fb3db96c8176e76268a8642be5842ee76ba6b762253504c385',
        "balance": 335
    },
    'kalash@gmail.com': {
        "name": 'Каля',
        # qwerty
        "password": '602bc7f8d94aaab0b46ad5d5b20aa7f7386047ccb9cf5d12cf58e09f491c3891',
        "balance": 111
    },
}


def sign_data(data: str) -> str:
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_b64, sign = username_signed.split('.')
    username = base64.b64decode(username_b64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    login_page = open('templates/login.html', 'r').read()

    # if get no cookie
    if not username:
        return Response(login_page, media_type="text/html")

    valid_username = get_username_from_signed_string(username)

    # if we got wrong cookie
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    return Response(f"Hi, {user['name']}", media_type="text/html")


@app.post("/login")
def login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)

    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": f"I do not know you!: {username}"
            }), media_type="application/json")
    else:
        response = Response(
            json.dumps({
                "success": True,
                "message": f"login: {username} <br/> balance: {user['balance']}"
            }), media_type="application/json")
        signed_username = base64.b64encode(username.encode()).decode() + '.' + sign_data(username)
        response.set_cookie(key="username", value=signed_username)
        return response
