ARG PYTHON_IMAGE=python:3.12-slim

FROM ${PYTHON_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
COPY requirements.lock /tmp/requirements.lock
RUN /opt/venv/bin/pip install --require-hashes --only-binary=:all: -r /tmp/requirements.lock

FROM ${PYTHON_IMAGE}
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    AUDITOR_DB_PATH=/var/lib/auditor/audits.db \
    AUDITOR_TRAINING_RULES=/var/lib/auditor/training_rules.json
RUN groupadd --system --gid 10001 auditor \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin auditor \
 && install -d -o 10001 -g 10001 -m 0750 /var/lib/auditor
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root auditor ./auditor
COPY --chown=root:root app ./app
COPY --chown=root:root data ./data
COPY --chown=root:root .streamlit ./.streamlit
USER 10001:10001
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health',timeout=3).status==200 else 1)"]
CMD ["streamlit", "run", "app/main.py", "--server.address=0.0.0.0", "--server.port=8501"]
