FROM python:3.15.0-slim-bookworm@sha256:0e019bbdfb5d9874cb2389f1c2884b64aa2ac97c99960b5bc521cef978c0617d AS dependencies
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
COPY requirements.lock /srv/requirements.lock
RUN pip install --require-hashes -r requirements.lock
RUN groupadd -g 10001 aegis && useradd -u 10001 -g aegis -M -s /usr/sbin/nologin aegis

FROM dependencies AS business
COPY apps/__init__.py /srv/apps/__init__.py
COPY apps/core /srv/apps/core
COPY scripts/__init__.py scripts/initialize.py /srv/scripts/
COPY alembic.ini /srv/alembic.ini
COPY infrastructure/database/migrations /srv/infrastructure/database/migrations
USER 10001:10001
EXPOSE 8080

FROM business AS hardened
COPY apps/hardened /srv/apps/hardened
CMD ["uvicorn", "apps.hardened.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-access-log", "--no-server-header"]

FROM business AS vulnerable
COPY apps/vulnerable /srv/apps/vulnerable
CMD ["uvicorn", "apps.vulnerable.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-access-log", "--no-server-header"]

FROM dependencies AS simulator
COPY apps/__init__.py /srv/apps/__init__.py
COPY apps/simulator /srv/apps/simulator
USER 10001:10001
CMD ["uvicorn", "apps.simulator.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--no-server-header"]

FROM dependencies AS control
COPY apps/__init__.py /srv/apps/__init__.py
COPY apps/core /srv/apps/core
COPY apps/lab_control /srv/apps/lab_control
COPY labs /srv/labs
RUN mkdir /data && chown 10001:10001 /data
USER 10001:10001
CMD ["uvicorn", "apps.lab_control.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--no-server-header"]
