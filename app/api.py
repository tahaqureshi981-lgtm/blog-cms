from fastapi import FastAPI, Body, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.auth.auth_bearer import JWTBearer
from app.auth.auth_handler import sign_jwt, sign_refresh_token, hash_password, verify_password, decode_jwt
from app.model import PostSchema, UserSchema, UserLoginSchema
from app.database import get_db, engine
from app import models

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RefreshTokenRequest(BaseModel):
    refresh_token: str


@app.get("/", tags=["root"])
async def read_root() -> dict:
    return {"message": "Welcome to your blog!"}


@app.get("/posts", tags=["posts"])
async def get_posts(db: Session = Depends(get_db)):
    posts = db.query(models.Post).all()
    return {"data": posts}


@app.get("/posts/{id}", tags=["posts"])
async def get_single_post(id: int, db: Session = Depends(get_db)):
    post = db.query(models.Post).filter(models.Post.id == id).first()
    if not post:
        return {"error": "No such post."}
    return {"data": post}


@app.post("/posts", dependencies=[Depends(JWTBearer())], tags=["posts"])
async def add_post(post: PostSchema, db: Session = Depends(get_db)):
    db_post = models.Post(title=post.title, content=post.content)
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return {"data": db_post}


@app.post("/user/signup", tags=["user"])
async def create_user(user: UserSchema = Body(...), db: Session = Depends(get_db)):
    db_user = models.User(
        fullname=user.fullname,
        email=user.email,
        password=hash_password(user.password)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    refresh_token = sign_refresh_token(db_user.email)
    db_user.refresh_token = refresh_token
    db.commit()
    return {
        "access_token": sign_jwt(db_user.email),
        "refresh_token": refresh_token
    }


@app.post("/user/login", tags=["user"])
async def user_login(user: UserLoginSchema = Body(...), db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(
        models.User.email == user.email
    ).first()
    if db_user and verify_password(user.password, db_user.password):
        refresh_token = sign_refresh_token(db_user.email)
        db_user.refresh_token = refresh_token
        db.commit()
        return {
            "access_token": sign_jwt(db_user.email),
            "refresh_token": refresh_token
        }
    return {"error": "Wrong login details!"}


@app.post("/user/refresh", tags=["user"])
async def refresh_token(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    token = request.refresh_token
    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")
    user_id = payload.get("user_id")
    db_user = db.query(models.User).filter(
        models.User.email == user_id,
        models.User.refresh_token == token
    ).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="Refresh token not recognised.")
    new_access_token = sign_jwt(db_user.email)
    return {"access_token": new_access_token}