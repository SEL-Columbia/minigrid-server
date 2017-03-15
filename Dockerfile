FROM python:3.6
COPY . /minigrid-server
WORKDIR /minigrid-server
RUN set -x \
  && pip install --no-cache-dir -r requirements.txt \
  && useradd -r -d /minigrid-server -s /sbin/nologin minigrid-server \
  && chown -R minigrid-server:minigrid-server .
USER minigrid-server
CMD ["./prod/run.sh"]
EXPOSE 8888
