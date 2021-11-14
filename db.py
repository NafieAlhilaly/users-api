import sqlalchemy as sql
import sqlalchemy.ext.declarative as declarative
import sqlalchemy.orm as orm


DATABASE_URL = "database url"
engine = sql.create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# return a function
session_local = orm.sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative.declarative_base()
