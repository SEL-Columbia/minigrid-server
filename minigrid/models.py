"""ORM models."""
from contextlib import contextmanager

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.exc import DataError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import func

import tornado.web

from minigrid.options import options


metadata = sa.MetaData(schema=options.db_schema)
Base = declarative_base(metadata=metadata)


sa.event.listen(
    Base.metadata, 'before_create',
    sa.DDL(f"""
        ALTER DATABASE {options.db_database} SET TIMEZONE TO "UTC";
        CREATE SCHEMA IF NOT EXISTS public;
        CREATE SCHEMA IF NOT EXISTS {options.db_schema};
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA pg_catalog;
    """))


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


def fk(foreign_column):
    """Return a foreign key."""
    return sa.Column(
        pg.UUID, sa.ForeignKey(foreign_column))


def json_column(column_name, default=None):
    """Return a JSONB column that is a dictionary at the top level."""
    return sa.Column(
        pg.json.JSONB,
        sa.CheckConstraint(f"{column_name} @> '{{}}'"),
        nullable=False,
        server_default=default)


def get_minigrids(session):
    """Return the minigrids ordered by name."""
    return session.query(Minigrid).order_by(Minigrid.minigrid_name)


def get_minigrid(session, minigrid_id, exception=tornado.web.HTTPError(404)):
    """Return a minigrid by ID, if it exists."""
    try:
        with transaction(session) as tx_session:
            return (
                tx_session.query(Minigrid)
                .filter_by(minigrid_id=minigrid_id).one())
    except (NoResultFound, DataError):
        if exception is None:
            raise
        raise exception


class User(Base):
    """The model for a registered user."""

    __tablename__ = 'user'
    user_id = pk()
    email = sa.Column(
        pg.TEXT, sa.CheckConstraint("email ~ '.*@.*'"),
        nullable=False, unique=True)


class System(Base):
    """The model for the entire system of minigrids."""

    __tablename__ = 'minigrid_system'
    system_id = sa.Column(
        pg.INTEGER, sa.CheckConstraint('system_id = 1'),
        primary_key=True, server_default='1')
    day_tariff = sa.Column(
        pg.NUMERIC,
        sa.CheckConstraint('day_tariff > 0'), nullable=False)
    day_tariff_start = sa.Column(
        pg.INTEGER,
        sa.CheckConstraint('day_tariff_start >= 0'),
        sa.CheckConstraint('day_tariff_start <= 23'),
        sa.CheckConstraint('day_tariff_start < night_tariff_start'),
        nullable=False, server_default='6')
    night_tariff = sa.Column(
        pg.NUMERIC,
        sa.CheckConstraint('night_tariff > 0'), nullable=False)
    night_tariff_start = sa.Column(
        pg.INTEGER,
        sa.CheckConstraint('night_tariff_start >= 0'),
        sa.CheckConstraint('night_tariff_start <= 23'),
        sa.CheckConstraint('night_tariff_start > day_tariff_start'),
        nullable=False, server_default='18')


class Minigrid(Base):
    """The model for a minigrid."""

    __tablename__ = 'minigrid'
    minigrid_id = pk()
    minigrid_name = sa.Column(
        pg.TEXT, sa.CheckConstraint("minigrid_name != ''"),
        nullable=False, unique=True)
    aes_key = sa.Column(
        pg.TEXT, sa.CheckConstraint("aes_key != ''"),
        nullable=False)
    error_code = json_column('error_code', default='{}')
    status = json_column('status', default='{}')

    vendors = relationship(
        'Vendor', backref='minigrid', order_by='Vendor.vendor_name')
    customers = relationship(
        'Customer', backref='minigrid', order_by='Customer.customer_name')


class Vendor(Base):
    """The model for a Vendor."""

    __tablename__ = 'vendor'
    vendor_id = pk()
    vendor_minigrid_id = fk('minigrid.minigrid_id')
    vendor_name = sa.Column(
        pg.TEXT, sa.CheckConstraint("vendor_name != ''"),
        nullable=False)
    vendor_user_id = sa.Column(
        pg.TEXT, sa.CheckConstraint("vendor_user_id ~ '\d{4}'"),
        nullable=False)

    __table_args__ = (
        sa.UniqueConstraint('vendor_minigrid_id', 'vendor_user_id'),
        sa.UniqueConstraint('vendor_minigrid_id', 'vendor_name'))


class Customer(Base):
    """The model for a customer."""

    __tablename__ = 'customer'
    customer_id = pk()
    customer_minigrid_id = fk('minigrid.minigrid_id')
    customer_name = sa.Column(
        pg.TEXT, sa.CheckConstraint("customer_name != ''"),
        nullable=False)

    __table_args__ = (
        sa.UniqueConstraint('customer_minigrid_id', 'customer_name'),)
