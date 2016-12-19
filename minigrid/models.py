"""ORM models."""
from contextlib import contextmanager

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql.functions import current_timestamp
from sqlalchemy.sql import func

from minigrid.options import options


metadata = sa.MetaData(schema=options.db_schema)
Base = declarative_base(metadata=metadata)


sa.event.listen(
    Base.metadata, 'before_create',
    sa.DDL("""
        ALTER DATABASE {} SET TIMEZONE TO "UTC";
        CREATE SCHEMA IF NOT EXISTS public;
        CREATE SCHEMA IF NOT EXISTS {};
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA pg_catalog;
    """.format(options.db_database, options.db_schema))
)


def create_engine():
    """Connect to the database using the application-level options."""
    connection_string = 'postgresql+psycopg2://{}:{}@{}:{}/{}'.format(
        options.db_user, options.db_password, options.db_host,
        options.db_port, options.db_database)
    return sa.create_engine(connection_string)


@contextmanager
def transaction(session):
    """Provide a transactional scope around a series of operations.

    Taken from http://docs.sqlalchemy.org/en/latest/orm/session_basics.html
    #when-do-i-construct-a-session-when-do-i-commit-it-and-when-do-i-close-it
    """
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise


def pk():
    """Return a primary key UUID column."""
    return sa.Column(
        pg.UUID, primary_key=True, server_default=func.uuid_generate_v4())


def update_time():
    """Return a timestamp column set to CURRENT_TIMESTAMP by default."""
    return sa.Column(
        pg.TIMESTAMP(timezone=True),
        nullable=False,
        server_default=current_timestamp(),
    )


def json_column(column_name, default=None):
    """Return a JSONB column that is a dictionary at the top level."""
    return sa.Column(
        pg.json.JSONB,
        sa.CheckConstraint("{} @> '{{}}'".format(column_name)),
        nullable=False,
        server_default=default,
    )


class User(Base):
    """The model for a registered user."""

    __tablename__ = 'user'
    user_id = pk()
    email = sa.Column(
        pg.TEXT, sa.CheckConstraint("email ~ '.*@.*'"),
        nullable=False, unique=True,
    )


class Minigrid(Base):
    """The model for a minigrid."""

    __tablename__ = 'minigrid'
    minigrid_id = pk()
    name = sa.Column(
        pg.TEXT, sa.CheckConstraint("name != ''"),
        nullable=False, unique=True)
    day_tariff = sa.Column(
        pg.NUMERIC,
        sa.CheckConstraint('day_tariff > 0'), nullable=False)
    day_tariff_update_time = update_time()
    night_tariff = sa.Column(
        pg.NUMERIC,
        sa.CheckConstraint('night_tariff > 0'), nullable=False)
    night_tariff_update_time = update_time()
    error_code = json_column('error_code', default='{}')
    status = json_column('status', default='{}')
