"""ORM models."""
from contextlib import contextmanager

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.exc import DataError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
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
    tariff_creation_timestamp = sa.Column(
        pg.TIMESTAMP, nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp())
    tariff_activation_timestamp = sa.Column(
        pg.TIMESTAMP, nullable=False,
        server_default=func.current_timestamp())


class VendorCardHistory(Base):
    """The model for freshly-minted vendor card records."""

    __tablename__ = 'vendor_card_history'
    vendor_card_id = pk()
    vendor_card_minigrid_id = sa.Column(pg.UUID, nullable=False)
    vendor_card_vendor_id = sa.Column(pg.UUID, nullable=False)
    vendor_card_user_id = sa.Column(
        pg.TEXT, sa.CheckConstraint("vendor_card_user_id ~ '\d{4}'"),
        nullable=False)
    vendor_card_created = sa.Column(
        pg.TIMESTAMP, nullable=False,
        server_default=func.current_timestamp())


class CustomerCardHistory(Base):
    """The model for freshly-minted customer card records."""

    __tablename__ = 'customer_card_history'
    customer_card_id = pk()
    customer_card_minigrid_id = sa.Column(pg.UUID, nullable=False)
    customer_card_customer_id = sa.Column(pg.UUID, nullable=False)
    customer_card_user_id = sa.Column(
        pg.TEXT, sa.CheckConstraint("customer_card_user_id ~ '\d{4}'"),
        nullable=False)
    customer_card_created = sa.Column(
        pg.TIMESTAMP, nullable=False,
        server_default=func.current_timestamp())


class MaintenanceCardHistory(Base):
    """The model for freshly-minted maintenance card records."""

    __tablename__ = 'maintenance_card_history'
    mc_id = pk()
    mc_minigrid_id = sa.Column(pg.UUID, nullable=False)
    mc_maintenance_card_id = sa.Column(pg.UUID, nullable=False)
    mc_maintenance_card_card_id = sa.Column(
        pg.TEXT, sa.CheckConstraint("mc_maintenance_card_card_id ~ '\d{4}'"),
        nullable=False)
    mc_created = sa.Column(
        pg.TIMESTAMP, nullable=False,
        server_default=func.current_timestamp())


class CreditCardHistory(Base):
    """The model for freshly-minted credit card records."""

    __tablename__ = 'credit_card_history'
    credit_card_id = pk()
    credit_minigrid_id = fk('minigrid.minigrid_id')
    credit_amount = sa.Column(
        pg.INTEGER,
        sa.CheckConstraint('credit_amount > 0'),
        nullable=False)
    credit_day_tariff = sa.Column(
        pg.NUMERIC,
        sa.CheckConstraint('credit_day_tariff > 0'), nullable=False)
    credit_day_tariff_start = sa.Column(
        pg.INTEGER,
        sa.CheckConstraint('credit_day_tariff_start >= 0'),
        sa.CheckConstraint('credit_day_tariff_start <= 23'),
        sa.CheckConstraint(
            'credit_day_tariff_start < credit_night_tariff_start'),
        nullable=False)
    credit_night_tariff = sa.Column(
        pg.NUMERIC,
        sa.CheckConstraint('credit_night_tariff > 0'), nullable=False)
    credit_night_tariff_start = sa.Column(
        pg.INTEGER,
        sa.CheckConstraint('credit_night_tariff_start >= 0'),
        sa.CheckConstraint('credit_night_tariff_start <= 23'),
        sa.CheckConstraint(
            'credit_night_tariff_start > credit_day_tariff_start'),
        nullable=False)
    credit_tariff_creation_timestamp = sa.Column(
        pg.TIMESTAMP, nullable=False)
    credit_tariff_activation_timestamp = sa.Column(
        pg.TIMESTAMP, nullable=False)
    credit_card_created = sa.Column(
        pg.TIMESTAMP, nullable=False,
        server_default=func.current_timestamp())


class SystemHistory(Base):
    """The model for information retrieved from used credit cards."""

    __tablename__ = 'system_history'
    sh_id = pk()
    sh_credit_card_id = fk('credit_card_history.credit_card_id')
    sh_meter_id = sa.Column(
        pg.INTEGER,
        sa.CheckConstraint('sh_meter_id > 0'), nullable=False)
    sh_meter_energy_usage = sa.Column(
        pg.INTEGER,
        sa.CheckConstraint('sh_meter_energy_usage >= 0'), nullable=False)
    sh_meter_credit = sa.Column(
        pg.INTEGER,
        sa.CheckConstraint('sh_meter_credit >= 0'), nullable=False)
    sh_record_timestamp = sa.Column(
        pg.TIMESTAMP, nullable=False)
    sh_created = sa.Column(
        pg.TIMESTAMP, nullable=False,
        server_default=func.current_timestamp())


class Device(Base):
    """The model for a device."""

    __tablename__ = 'device'
    address = sa.Column(
        pg.BYTEA, sa.CheckConstraint("length(address) = 6"),
        primary_key=True)


class PaymentSystem(Base):
    """The model for pregenerated payment system IDs."""

    __tablename__ = 'payment_system'
    payment_id = pk()
    aes_key = sa.Column(
        pg.BYTEA, sa.CheckConstraint("length(aes_key) = 32"),
        nullable=False)


class Minigrid(Base):
    """The model for a minigrid."""

    __tablename__ = 'minigrid'
    minigrid_id = pk()
    minigrid_name = sa.Column(
        pg.TEXT, sa.CheckConstraint("minigrid_name != ''"),
        nullable=False, unique=True)
    minigrid_payment_id = fk('payment_system.payment_id')
    error_code = json_column('error_code', default='{}')
    status = json_column('status', default='{}')

    payment_system = relationship(
        'PaymentSystem', backref=backref('minigrid', uselist=False))
    vendors = relationship(
        'Vendor', backref='minigrid', order_by='Vendor.vendor_user_id')
    customers = relationship(
        'Customer', backref='minigrid', order_by='Customer.customer_user_id')
    maintenance_cards = relationship(
        'MaintenanceCard', backref='minigrid',
        order_by='MaintenanceCard.maintenance_card_card_id')

    __table_args__ = (
        sa.UniqueConstraint('minigrid_payment_id'),)


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
    customer_user_id = sa.Column(
        pg.TEXT, sa.CheckConstraint("customer_user_id ~ '\d{4}'"),
        nullable=False)
    customer_current_limit = sa.Column(
        pg.TEXT,
        sa.CheckConstraint("customer_current_limit >= 0"),
        nullable=False)
    customer_energy_limit = sa.Column(
        pg.TEXT,
        sa.CheckConstraint("customer_energy_limit >= 0"),
        nullable=False)

    __table_args__ = (
        sa.UniqueConstraint('customer_minigrid_id', 'customer_user_id'),
        sa.UniqueConstraint('customer_minigrid_id', 'customer_name')),
        sa.UniqueConstraint('customer_minigrid_id', 'customer_current_limit')),
        sa.UniqueConstraint('customer_minigrid_id', 'customer_energy_limit'))


class MaintenanceCard(Base):
    """The model for a maintenance card."""

    __tablename__ = 'maintenance_card'
    maintenance_card_id = pk()
    maintenance_card_minigrid_id = fk('minigrid.minigrid_id')
    maintenance_card_name = sa.Column(
        pg.TEXT, sa.CheckConstraint("maintenance_card_name != ''"),
        nullable=False)
    maintenance_card_card_id = sa.Column(
        pg.TEXT, sa.CheckConstraint("maintenance_card_card_id ~ '\d{4}'"),
        nullable=False)

    __table_args__ = (
        sa.UniqueConstraint(
            'maintenance_card_minigrid_id', 'maintenance_card_card_id'),
        sa.UniqueConstraint(
            'maintenance_card_minigrid_id', 'maintenance_card_name'))
