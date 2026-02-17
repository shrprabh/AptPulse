# database.py
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

load_dotenv()  # loads .env into environment variables

URL_DATABASE = os.getenv("URL_DATABASE")
if not URL_DATABASE:
    raise ValueError("URL_DATABASE not found. Put it in .env or export it in your shell.")

engine = create_engine(
    URL_DATABASE,
    pool_pre_ping=True,
    future=True
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()
