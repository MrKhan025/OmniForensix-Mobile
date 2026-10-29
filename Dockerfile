FROM python:3.12-slim

LABEL org.opencontainers.image.title="OmniForensix-Mobile"
LABEL org.opencontainers.image.description="Post-acquisition mobile forensics and artifact analysis framework"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd -r forensics && useradd -r -g forensics -m analyst
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir . && \
    mkdir -p /evidence /output && \
    chown -R analyst:forensics /app /output

USER analyst
VOLUME ["/evidence", "/output"]
ENTRYPOINT ["omniforensix"]
CMD ["--help"]
