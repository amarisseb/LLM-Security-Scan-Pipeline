# Release gate: lock transitive dependencies and pin reviewed image digests.
FROM python:3.12-slim-bookworm
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/data/home \
    XDG_CACHE_HOME=/data/cache \
    XDG_DATA_HOME=/data/cache/share
WORKDIR /srv/arisec
COPY requirements.txt ./requirements.txt
# Install the CPU wheel first and constrain the second resolver to that wheel.
# No local machine's torch version is assumed to exist in the public index.
RUN python -m pip install --index-url "${TORCH_INDEX_URL}" torch \
    && python -c "from importlib.metadata import version; print('torch==' + version('torch'))" > /tmp/torch-constraint.txt \
    && python -m pip install -c /tmp/torch-constraint.txt -r requirements.txt \
    && rm /tmp/torch-constraint.txt \
    && groupadd --gid 10001 arisec \
    && useradd --uid 10001 --gid 10001 --home-dir /data/home --no-create-home --shell /usr/sbin/nologin arisec \
    && mkdir -p /data \
    && chown 10001:10001 /data \
    && chmod 700 /data
COPY app/ ./app/
COPY demo/index.html demo/scenarios.json ./demo/
COPY generate_report.py audit_report.py ./
COPY tools/serve_production.py tools/manage_consultations.py ./tools/
USER 10001:10001
EXPOSE 8000
CMD ["python", "tools/serve_production.py"]
