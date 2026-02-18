from logging.config import fileConfig
import os
from dotenv import load_dotenv

from sqlalchemy import engine_from_config, pool
from alembic import context

# Load .env so URL_DATABASE is available
load_dotenv()

config = context.config

# Set DB URL from env var
db_url = os.getenv("URL_DATABASE")
if not db_url:
    raise RuntimeError("URL_DATABASE not found in environment/.env")
config.set_main_option("sqlalchemy.url", db_url.replace("%", "%%"))

# Logging setup
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# IMPORTANT:
# Import Base from database.py (single source of truth)
from database import Base  # noqa: E402

# Import models so all tables are registered on Base.metadata
import models  # noqa: E402,F401

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,  # helpful for detecting type changes
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
