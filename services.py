import os
import jwt
import db
import models
import fastapi
from dotenv import load_dotenv
import sqlalchemy.orm as orm
import passlib.hash as _hash
import fastapi.security as security
from fastapi import BackgroundTasks
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

# load .env variables
load_dotenv()

oauth2schema = security.OAuth2PasswordBearer(tokenUrl="/api/token")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

# mail config
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
MAIL_FROM = os.getenv('MAIL_FROM')
MAIL_PORT = int(os.getenv('MAIL_PORT'))
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_FROM_NAME = os.getenv('MAIN_FROM_NAME')

conf = ConnectionConfig(
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD,
    MAIL_FROM=MAIL_FROM,
    MAIL_PORT=MAIL_PORT,
    MAIL_SERVER=MAIL_SERVER,
    MAIL_FROM_NAME=MAIL_FROM_NAME,
    MAIL_TLS=True,
    MAIL_SSL=False,
    USE_CREDENTIALS=True,
    TEMPLATE_FOLDER='./templates'
)

def send_email(background_tasks: BackgroundTasks, subject: str, email_to: str, body: dict):
    """
    create a background task to send email to new user/users
    """
    message = MessageSchema(
        subject=subject,
        recipients=[email_to],
        body=body,
        subtype='html',
    )
    fm = FastMail(conf)
    background_tasks.add_task(
       fm.send_message, message, template_name='email.html')

def create_database():
    """
    create database if not exists
    
    """
    return db.Base.metadata.create_all(bind=db.engine)


def get_db():
    database = db.session_local()
    try:
        yield database
    finally:
        database.close()


async def get_user_by_email(email: str, db: orm.Session):
    """
    get user information by email

    :param email: user email
    :param db: database session object

    :return: user information
    """
    return db.query(models.User).filter(models.User.email == email).first()


async def create_user(name: str, email: str, password: str, db: orm.Session) -> models.User:
    """
    create a new user with the form data received

    :param name: user name
    :param email: user email
    :param password: user password
    :param db: database session object

    :return: new user
    """

    user_obj = models.User(name=name, email=email, hashed_password=_hash.bcrypt.hash(password))
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    
    send_email(
        background_tasks, 
        'Hello World','someemail@gmail.com', 
        {'title': 'Hello World', 'name':name})

    return user_obj


async def authenticate_user(email: str, password: str, db: orm.Session) -> dict:
    """
    Authenticate current signed user

    :param email: user email
    :param password: user pass
    :param db: database session object

    :return: dict of user and success of fail message
    """

    user = await get_user_by_email(email=email, db=db)
    if not user:
        return {"user": None, "message": "User not found"}
    if not user.verify_password(password):
        return {"user": None, "message": "Incorrect password"}
    return {"user": user, "message": "Authenticated"}


async def create_token(user: models.User) -> dict:
    """
    create token for a user

    :param user: User Object

    :return: dict of token
    """

    user_dict = {
        "name": user.name,
        "email": user.email,
        "id": user.id
    }
    token = jwt.encode(user_dict, JWT_SECRET_KEY)
    return dict(access_token=token, token_type="bearer")


async def get_current_user(
        token: str = fastapi.Depends(oauth2schema),
        db: orm.Session = fastapi.Depends(get_db)) -> dict:

    """
    return current user

    :param token: user token
    :param db: database session object

    :return: dict of user information
    """

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        user = db.query(models.User).get(payload['id'])
    except fastapi.HTTPException:
        raise fastapi.HTTPException(status_code=401, detail="Invalid User")
    user = {
        "id": user.id,
        "name": user.name,
        "email": user.email
    }
    return user
