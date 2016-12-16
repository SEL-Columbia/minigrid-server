#!/usr/bin/env python
"""Commands useful during development."""
import argparse
import os
import sys

from sqlalchemy.orm import sessionmaker

sys.path.insert(1, os.path.join(sys.path[0], '..'))


def createdb(ensure=True):
    """Create the schema and tables and return a Session."""
    from minigrid import models
    engine = models.create_engine()
    if ensure:
        models.Base.metadata.create_all(engine)
        print('Created schema {}'.format(models.Base.metadata.schema))
    return sessionmaker(bind=engine)()


def create_user(*, email):
    """Create a user with the given e-mail."""
    from minigrid import models
    session = createdb(ensure=False)
    with session.begin_nested():
        session.add(models.User(email=email))
    print('Created user with e-mail ' + email)


def killdb():
    """Drop the schema."""
    from minigrid import models
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
    args, others = parser.parse_known_args()
    from minigrid.options import parse_command_line
    parse_command_line([None] + others)
    from minigrid.options import options
    if not any(other.startswith('--db_schema=') for other in others):
        options.db_schema = 'minigrid_dev'
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
