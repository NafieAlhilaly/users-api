import fastapi
from fastapi import FastAPI, Form
import fastapi.security as security
import sqlalchemy.orm as orm
import services

app = FastAPI()


@app.post("/api/users")
async def create_user(
        name: str = Form(...),
        email: str = Form(...),
        password: str = Form(...),
        db: orm.Session = fastapi.Depends(services.get_db)):

    """
    user creation endpoint

    :param name, email and password: Form data
    :param db: database session url

    :return:
        if user is already exist HTTPException will be raised
        otherwise a new user will be created and its token
    """

    is_user_exist = await services.get_user_by_email(email, db)
    if is_user_exist:
        raise fastapi.HTTPException(status_code=400, detail="User Already exits!")
    user = await services.create_user(name=name, email=email, password=password, db=db)
    return await services.create_token(user)


@app.post("/api/token")
async def generate_token(form_data: security.OAuth2PasswordRequestForm = fastapi.Depends(),
                         db: orm.Session = fastapi.Depends(services.get_db)):

    """
    token generating endpoint

    :param form_data: user info(email and password
    :param db: database session object

    :return:
        if user is not exits it will raise HTTPException, otherwise user will be
        given a new token
    """

    user = await services.authenticate_user(form_data.username, form_data.password, db)

    if user['user'] is None:
        raise fastapi.HTTPException(status_code=401, detail=user["message"])
    return await services.create_token(user["user"])


@app.get(f"/api/users/me")
async def get_current_user(user=fastapi.Depends(services.get_current_user)):
    """
    current user endpoint

    :param user: user data from database
    :return:
        dict of current user data
    """
    return user


