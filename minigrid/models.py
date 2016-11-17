"""ORM models."""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.ext.declarative import declarative_base
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


def pk():
    """Return a primary key UUID column."""
    return sa.Column(
        pg.UUID, primary_key=True, server_default=func.uuid_generate_v4())


class User(Base):
    __tablename__ = 'user'
    user_id = pk()
    email = sa.Column(
        pg.TEXT, sa.CheckConstraint("email ~ '.*@.*'"),
        nullable=False, unique=True,
    )
