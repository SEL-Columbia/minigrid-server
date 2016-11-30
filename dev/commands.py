#!/usr/bin/env python
"""Commands useful during development."""
import argparse
import os
import sys

from sqlalchemy.orm import sessionmaker

sys.path.insert(1, os.path.join(sys.path[0], '..'))


if __name__ == '__main__':
    from minigrid.options import parse_command_line
    parse_command_line()
from minigrid.options import options  # noqa
options.db_schema = 'minigrid_dev'
from minigrid import models  # noqa


def createdb():
    """Create the schema and tables and return a Session."""
    engine = models.create_engine()
    models.Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autocommit=True)()


def create_user(*, email):
    """Create a user with the given e-mail."""
    session = createdb()
    with session.begin():
        session.add(models.User(email=email))
    print('Created user with e-mail ' + email)


def killdb():
    """Drop the schema."""
    answer = input('You definitely want to kill the schema minigrid_dev? y/N ')
    if not answer.lower().startswith('y'):
        print('Not dropping the schema')
        return
    engine = models.create_engine()
    engine.execute('DROP SCHEMA minigrid_dev CASCADE')
    print('Dropped schema')


def main():
    """Choose the command to run."""
    parser = argparse.ArgumentParser()
    parser.add_argument('command_name')
    parser.add_argument('--kwarg', action='append')
    args = parser.parse_args()
    try:
        command = globals()[args.command_name]
        if args.kwarg:
            command(**dict(kv.split('=') for kv in args.kwarg))
        else:
            command()
    except KeyError:
        print(args.command_name + ' is not a command.')


if __name__ == '__main__':
    main()
