#!/usr/bin/env python
"""Create the initial administrator for the application."""
import argparse
import os
import sys

from sqlalchemy import func
from sqlalchemy.orm import sessionmaker

sys.path.insert(1, os.path.join(sys.path[0], '..'))


def main():
    """Supply the administrator's e-mail"""
    parser = argparse.ArgumentParser()
    parser.add_argument('email')
    args, others = parser.parse_known_args()
    from minigrid.options import parse_command_line
    parse_command_line([None] + others)
    from minigrid.options import options
    if not any(other.startswith('--db_schema=') for other in others):
        options.db_schema = 'minigrid_dev'
    from minigrid import models
    engine = models.create_engine()
    session = sessionmaker(bind=engine, autocommit=True)()
    users = session.query(func.count(models.User.user_id)).scalar()
    if users:
        print('At least one user already exists. Log in as that user.')
        sys.exit(1)
    with session.begin():
        session.add(models.User(email=args.email))
    print('Created initial user with e-mail', args.email)


if __name__ == '__main__':
    main()
