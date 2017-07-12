#!/usr/bin/env python
"""Create the payment IDs and AES keys for the application."""
import argparse
import io
import os
import secrets
import sys
from time import sleep

from sqlalchemy import func
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

sys.path.insert(1, os.path.join(sys.path[0], '..'))


def _aes_key():
    """Generate an AES key that PostgreSQL COPY FROM will like."""
    return r'\\x{}'.format(secrets.token_bytes(32).hex())


def main():
    """Generate 100,000 AES keys."""
    parser = argparse.ArgumentParser()
    _, others = parser.parse_known_args()
    from minigrid.options import parse_command_line
    parse_command_line([None] + others)
    from minigrid.options import options
    if not any(other.startswith('--db_schema=') for other in others):
        options.db_schema = 'minigrid'
    from minigrid import models
    engine = models.create_engine()
    session = sessionmaker(bind=engine)()
    try:
        existing = session.query(
            func.count(models.PaymentSystem.payment_id)).scalar()
    except OperationalError:
        print('Database connection failed... trying again in 5 seconds.')
        sleep(5)
        existing = session.query(
            func.count(models.PaymentSystem.payment_id)).scalar()
    print('{} existing payment IDs in the system.'.format(existing))
    with models.transaction(session) as tx_session:
        cursor = tx_session.connection().connection.cursor()
        table = '{}.payment_system'.format(options.db_schema)
        aes_keys = io.StringIO('\n'.join(_aes_key() for _ in range(100000)))
        cursor.copy_from(aes_keys, table, columns=['aes_key'])
    now = session.query(func.count(models.PaymentSystem.payment_id)).scalar()
    print('{} payment IDs in the system now.'.format(now))


if __name__ == '__main__':
    main()
