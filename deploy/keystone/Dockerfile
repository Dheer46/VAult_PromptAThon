# Minimal OpenStack Keystone (2024.2 "Dalmatian") served by gunicorn, backed by MariaDB.
FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libffi-dev \
        default-mysql-client curl && rm -rf /var/lib/apt/lists/*
# Keystone only works with the library versions of its release, so install against the
# official 2024.2 upper-constraints (no unconstrained fallback: a mismatch must fail the build).
RUN pip install --no-cache-dir -c https://releases.openstack.org/constraints/upper/2024.2 \
        "keystone==26.0.0" python-openstackclient pymysql gunicorn \
    && python -c "import keystone.server.wsgi, oslo_context, bcrypt; print('keystone deps OK', bcrypt.__version__)"
RUN mkdir -p /etc/keystone /var/log/keystone
COPY keystone.conf /etc/keystone/keystone.conf
COPY entrypoint.sh /entrypoint.sh
COPY wsgi.py /opt/keystone/wsgi.py
RUN chmod +x /entrypoint.sh
EXPOSE 5000
HEALTHCHECK --interval=10s --timeout=3s --start-period=120s CMD curl -fs http://localhost:5000/v3 || exit 1
ENTRYPOINT ["/entrypoint.sh"]
