#!/usr/bin/env python
"""Simulate requests from the device."""
import argparse
import http.client
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from sqlalchemy.orm import sessionmaker

sys.path.insert(1, os.path.join(sys.path[0], '..'))

AES = algorithms.AES


#def createdb(ensure=True):
#    """Create the schema and tables and return a Session."""
#    from minigrid import models
#    engine = models.create_engine()
#    if ensure:
#        models.Base.metadata.create_all(engine)
#        print(f'Created schema {models.Base.metadata.schema}')
#    return sessionmaker(bind=engine)()
#
#
#def create_user(*, email):
#    """Create a user with the given e-mail."""
#    from minigrid import models
#    session = createdb(ensure=False)
#    with models.transaction(session) as tx_session:
#        tx_session.add(models.User(email=email))
#    print('Created user with e-mail ' + email)
#
#
#def killdb():
#    """Drop the schema."""
#    from minigrid import models
#    answer = input('You definitely want to kill the schema minigrid_dev? y/N ')
#    if not answer.lower().startswith('y'):
#        print('Not dropping the schema')
#        return
#    engine = models.create_engine()
#    engine.execute('DROP SCHEMA minigrid_dev CASCADE')
#    print('Dropped schema')
def block_info(argument):
    if not re.match('^[a-fA-F\d]=.+$', argument):
        msg = (
            f"'{argument}' is not of the form block_number=value, where"
            " block_number is 1 capital hex digit"
        )
        raise argparse.ArgumentTypeError(msg)
    return argument
    
def keep_posting(**blocks):
    """POST the information every few seconds."""
    assert False, blocks


def main():
    """Supply the information to POST."""
    parser = argparse.ArgumentParser()
    parser.add_argument('block', type=block_info, nargs='+')
    args, others = parser.parse_known_args()
    from minigrid.options import parse_command_line
    parse_command_line([None] + others)
    from minigrid.options import options
    if not any(other.startswith('--db_schema=') for other in others):
        options.db_schema = 'minigrid_dev'
    keep_posting(**dict(kv.split('=', 1) for kv in args.block))


if __name__ == '__main__':
    main()
