# P0-8 supply-chain: pin the base image by DIGEST (not the mutable :3.12-slim tag) and run as a
# non-root user. The digest is python:3.12-slim resolved 2026-07; re-resolve on a deliberate base bump.
FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

WORKDIR /app

# non-root runtime user (P0-8): create an unprivileged user up front and drop to it before CMD.
RUN groupadd -r app && useradd -r -g app -u 10001 app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app agent.py .
ENV PYTHONUNBUFFERED=1

USER 10001
CMD ["opentelemetry-instrument", "python", "-u", "agent.py"]
