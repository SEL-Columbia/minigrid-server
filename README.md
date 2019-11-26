# minigrid-server
Shared Solar server

## Running locally

### Native

```
$ python3.7 -m venv venv
$ source venv/bin/activate
(venv) $ pip install -r requirements.txt -r dev/requirements.txt
(venv) $ ./dev/run.sh
[I 170329 16:07:16 server:28] Debug mode is on
Listening on port 8889
[I 170329 16:07:16 server:50] Application started
```

### Docker

```
$ docker-compose -f dev/docker-compose.yml up -d
$ docker-compose -f dev/docker-compose.yml ps
     Name                   Command               State           Ports          
--------------------------------------------------------------------------------
dev_db_1         docker-entrypoint.sh postgres    Up      5432/tcp               
dev_minigrid_1   ./dev/run.sh --db_host=db  ...   Up      0.0.0.0:8889->8889/tcp
dev_redis_1      docker-entrypoint.sh redis ...   Up      6379/tcp               
```


## Adding an initial user locally

Note that the login flow is quicker with a gmail.com e-mail address.

### Native

```
(venv) $ ./dev/commands.py create_user --kwarg email=<your_email_address>
Created user with e-mail your_email_address
```

### Docker

```
$ docker exec dev_minigrid_1 dev/commands.py create_user --db_host=db --kwarg email=<your_email_address>
Created user with e-mail your_email_address
```

## Restoring Database from backup

* download backup, from S3 or otherwise
* use `scp` to copy the db from your host computer to the new server,

```
$ scp <BACKUP name> <USER>@<HOSTNAME>:<PATH on server>
```

* break connections, remove old db, and recreate so its blank

```
$ docker exec root_db_1 psql -U postgres -d minigrid -c "SELECT pid, pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid();"
$ docker exec root_db_1 psql -U postgres -c "DROP DATABASE minigrid"
$ docker exec root_db_1 psql -U postgres -c "CREATE DATABASE minigrid"
```

* copy backup into the database container

```
$ docker cp demo.sharedsolar.org-db-bak-11-26.pg root_db_1:/demo.sharedsolar.org-db-bak-11-26.pg
```

* restore the backup and restart the containers

```
$ docker exec root_db_1 psql -U postgres -d minigrid --set ON_ERROR_STOP=on -f demo.sharedsolar.org-db-bak-11-26.pg
$ docker restart $(docker ps -a -q)
```
