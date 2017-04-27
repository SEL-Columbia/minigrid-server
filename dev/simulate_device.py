#!/usr/bin/env python
"""Simulate requests from the device."""
import argparse
import os
import re
import sys
from time import sleep
from urllib.error import URLError
from urllib.request import urlopen
from uuid import UUID

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from sqlalchemy.orm import sessionmaker

from commands import createdb

sys.path.insert(1, os.path.join(sys.path[0], '..'))

AES = algorithms.AES

def uuid_string(minigrid_id):
    return str(UUID(minigrid_id))


def block_info(argument):
    if not re.match('^[a-fA-F\d]=.+$', argument):
        msg = (
            f"'{argument}' is not of the form block_number=value, where"
            " block_number is 1 hex digit"
        )
        raise argparse.ArgumentTypeError(msg)
    return argument


def check_for_duplicates(blocks):
    seen = set()
    for raw_key, value in blocks:
        key = int(raw_key, 16)
        if key in seen:
            raise argparse.ArgumentTypeError(f"duplicate block '{raw_key}'")
        seen.add(key)


def get_minigrid(minigrid_id):
    from minigrid.models import get_minigrid
    session = createdb(ensure=False)
    return get_minigrid(session, minigrid_id)


def keep_posting(endpoint, minigrid_id, **blocks):
    """POST the information every few seconds."""
    msg = f'Connection refused at {endpoint}. Is the server running?'
    minigrid = get_minigrid(minigrid_id)
    assert False, minigrid.payment_system.aes_key
    while True:
        print('POSTing card info')
        try:
            response = urlopen(endpoint, data=b'deadbeef')
        except URLError as error:
            if isinstance(error.reason, ConnectionRefusedError):
                print(msg)
            else:
                raise
        else:
            print(response.read())
        sleep(2)


def main():
    """Supply the information to POST."""
    parser = argparse.ArgumentParser()
    parser.add_argument('minigrid_id', type=uuid_string)
    parser.add_argument('--endpoint', default='http://localhost:8888')
    parser.add_argument('block', type=block_info, nargs='+')
    args, others = parser.parse_known_args()
    from minigrid.options import parse_command_line
    parse_command_line([None] + others)
    from minigrid.options import options
    if not any(other.startswith('--db_schema=') for other in others):
        options.db_schema = 'minigrid_dev'
    blocks = [kv.split('=', 1) for kv in args.block]
    check_for_duplicates(blocks)
    keep_posting(args.endpoint, args.minigrid_id, **dict(blocks))


if __name__ == '__main__':
    main()
