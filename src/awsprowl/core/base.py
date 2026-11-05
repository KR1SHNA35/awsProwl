"""Database base configuration for awsProwl."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine.base import Engine
from sqlalchemy.orm import declarative_base, sessionmaker

from awsprowl.core.config import get_config

# Get database path from config
config = get_config()
data_dir = config.get_data_dir()
data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

DATABASE_FILE_PATH = data_dir / "sqlite.db"
DATABASE_CONNECTION_PATH = f"sqlite:///{DATABASE_FILE_PATH}"

engine: Engine = create_engine(DATABASE_CONNECTION_PATH, echo=False)
Session: sessionmaker = sessionmaker(bind=engine)

Base = declarative_base()
