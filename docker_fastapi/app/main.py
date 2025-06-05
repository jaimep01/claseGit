from typing import List, Dict

import requests

from fastapi import Depends, FastAPI, HTTPException, Response, status
from sqlalchemy.orm import Session
import asyncio
import re

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
                &emsp;localhost/sleep/10 -> will sleep for 10 seconds<br><br>
            
            You can request a site and get general information like request time as well as some otehr neat info!<br>
            usage:<br>
                &emsp;localhost/request/&lt;http|https&gt;/&lt;IP|FQDN&gt;:&lt;Port#|NOPORT#&gt;<br>
            example:<br>
            &emsp;localhost/request/http/google.com<br>
            &emsp;localhost/request/https/google.com<br>
            &emsp;localhost/request/https/facebook.com:443<br>
            &emsp;localhost/request/http/portquiz.net:8080<br>

        </h2>
        <h3  style="padding-left: 2em;"> localhost/docs -> has an interactive window </h3> 
        <h3  style="padding-left: 2em;"> local server listens on port 8000 by default if no changes are made </h3>
        <h3  style="padding-left: 2em;"> Examples will use the IP or dns of your actual implementation not localhost! ex: myip.com/code/200 | mysvc/code/200</h3> 
        """
    return Response(content=body, media_type="text/html")


@app.get("/code/{code}")
async def generateCode(code: str, response: Response):
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


@app.get("/request/{protocol}/{destination}")
async def requestIP(protocol: str, destination: str, response: Response):
    """Request an IP or FQDN

    Args:
        protocol: http or https
        destination: Can be an IP or DNS, it can include a specific port number ex:8080
        response: fastapi response class

    """

    # If the request is an IP we append the default port number
    if re.search("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", destination):
        match protocol:
            case "https":
                url = protocol + "://" + destination + ":443"
            case "http":
                url = protocol + "://" + destination + ":80"
    # If not we reqest as is it might include or not the port number, the protocl is important.
    else:
        url = protocol + "://" + destination

    r = requests.get(
        url,
        stream=True,
        verify=False,
    )
    all_headers = ""
    for header in r.headers:
        all_headers = (
            all_headers
            + f"<dt>{header}</dt>"
            + f"<dd>⤷ {r.headers[header]}</dd>"
            + "<br>"
        )
    try:
        dns = r.raw._connection.sock.getpeername()

    except Exception as E:
        dns = "_not_fond_in_request"
        print(E)
    # TODO: do this a template
    body = f"""
    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet"
            integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
        <title>Reacher Test!</title>
    </head>

    <body>
        <div class="container p-4">
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"
                integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"
                crossorigin="anonymous"></script>
            <p><h1>You reached: {url}<br><br> 
                DNS to IP {dns} </h1><small class="text-muted">(If port does not match it might due to redirection, if not_found this could be due to the server response)</small></p>
            <br>
            <h2>The <a>elapsed</a> time was {r.elapsed}<br><br>
                The response code was {r.status_code}</h2><br>
            <p><a class="btn btn-primary" data-bs-toggle="collapse" href="#collapseHeaders" role="button"
                    aria-expanded="false" aria-controls="collapseHeaders">Headers</a></p>
            <div class="collapse" id="collapseHeaders">
                <div class="card card-body">
                    <dt>{all_headers}</dt>
                </div>
            </div>
            <dl>

            </dl>
            <p><a class="btn btn-primary" data-bs-toggle="collapse" href="#collapseResponse" role="button"
                    aria-expanded="false" aria-controls="collapseResponse">Response</a></p>
            <div class="collapse" id="collapseResponse">
                <div class="card card-body">
                    {r.text}
                </div>
            </div>
        </div>
    </body>

    </html>
    """
    return Response(content=body, media_type="text/html")


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
