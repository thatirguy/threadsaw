FROM python:3.13-slim-bookworm

LABEL org.opencontainers.image.title="Threadsaw" \
      org.opencontainers.image.version="1.3.0" \
      org.opencontainers.image.description="Offline static email triage; no URL/IP following or attachment execution"

ENV NO_PROXY="*" no_proxy="*"

ARG THREADSAW_INSTALL_MSG=0
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpst4 pst-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/threadsaw
COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md ./
COPY src ./src
RUN if [ "$THREADSAW_INSTALL_MSG" = "1" ]; then pip install --no-cache-dir '.[msg]'; else pip install --no-cache-dir .; fi

RUN useradd --create-home --uid 10001 threadsaw
USER threadsaw
ENTRYPOINT ["threadsaw"]
CMD ["--help"]
