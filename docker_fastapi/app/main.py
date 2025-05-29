from typing import List, Dict

from fastapi import Depends, FastAPI, HTTPException, Response, status
from sqlalchemy.orm import Session
import asyncio
import os

from . import crud, models, schemas
from .database import SessionLocal, engine

app = FastAPI()


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/", status_code=200)
async def root():
    body = f"""
        
        <h1 style="padding-left: 2em;"> Hello World this is a status code generation server <h1/>
        <h2 style="padding-left: 5em;">
            <p>
            This will simulate common behaviors that you see in prod servers,<br>
            usage:<br>
                &emsp;localhost/code/&lt;status code&gt;<br>
            examples:<br>
                &emsp;localhost/code/200 -> 200<br>
                &emsp;localhost/code/403 -> 403<br>
                &emsp;localhost/code/502 -> 502
            </p>
        </h2><br>
        <h2 style="padding-left: 5em;">
            There are some other useful  functions like making a requests<br>
            with a set timeout to check for load balancer or ingress,<br>
            timeout settings, NOTE: sleep will always send 200 codes.<br>
            usage:<br>
                &emsp;localhost/sleep/&lt;time in seconds&gt;<br>
            example:<br>
                &emsp;localhost/sleep/10 -> will sleep for 10 seconds<br>
        </h2>
        <h3> localhost/docs -> has an interactive window </h3> 
        <h3> local server listens on port 8000 by default if no changes are done </h3>
        """
    return Response(content=body, media_type="text/html")


@app.get("/code/{code}")
async def myCode(code: str, response: Response):
    response.status_code = int(code)
    if code == "418":
        body = f"""
        <h1>
            I am a tea cup!
        </h1>
        """
    else:
        body = f"""
        <h1>
            You generated a code {code}
        </h1>
        """
    return Response(content=body, media_type="text/html", status_code=int(code))


# @app.post("/users/create", response_model=schemas.UserCreate)
# def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
#     db_user = crud.get_user_by_id(db, user.id)
#     if db_user:
#         raise HTTPException(status_code=400, detail="User already registered")
#     return crud.create_user(db=db, user=user)

# @app.post("/users/{user_id}/", response_model=schemas.UserBase)
# def get_user_by_id(user_id: int, db: Session = Depends(get_db)):
#     return crud.get_user(db=db, user_id=user_id)

# @app.get("/users/", response_model=List[schemas.UserData])
# async def get_users(db: Session = Depends(get_db)):
#     return crud.get_all_users(db=db)


@app.get("/sleep/{sleep_time}", status_code=200)
async def sleep(sleep_time: str, respnse: Response):
    await asyncio.sleep(int(sleep_time))
    body = f"""
    <h1>
        Hello you slept for {sleep_time} seconds!
    </h1>
    """
    return Response(content=body, media_type="text/html")
