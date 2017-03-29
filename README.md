# minigrid-server
Shared Solar server

## Running locally

### Native

```
$ python3.6 -m venv venv
$ source venv/bin/activate
(venv) $ pip install -r requirements.txt -r dev/requirements.txt
(venv) $ ./dev/run.sh 
[I 170329 16:07:16 server:28] Debug mode is on
Listening on port 8888
[I 170329 16:07:16 server:50] Application started
```

### Docker

```
$ docker-compose -f dev/docker-compose.yml up -d
$ docker-compose -f dev/docker-compose.yml ps
     Name                   Command               State           Ports          
--------------------------------------------------------------------------------
dev_db_1         docker-entrypoint.sh postgres    Up      5432/tcp               
dev_minigrid_1   ./dev/run.sh --db_host=db  ...   Up      0.0.0.0:8888->8888/tcp 
dev_redis_1      docker-entrypoint.sh redis ...   Up      6379/tcp
```
