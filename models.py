import datetime
import sqlalchemy as sql
import passlib.hash as hash
import db


class User(db.Base):
    """
    Users class to map users to database
    """
    __tablename__ = "users"
    id = sql.Column(sql.Integer, primary_key=True, index=True)
    name = sql.Column(sql.String)
    email = sql.Column(sql.String, unique=True)
    hashed_password = sql.Column(sql.String)
    date_created = sql.Column(sql.DateTime, default=datetime.datetime.utcnow())

    def verify_password(self, password: str) -> bool:
        return hash.bcrypt.verify(password, self.hashed_password)
