FROM python:3.13-slim-bookworm

ARG THREADSAW_VERSION=1.3.0
ARG VCS_REF=""
LABEL org.opencontainers.image.title="Threadsaw" \
      org.opencontainers.image.version="${THREADSAW_VERSION}" \
      org.opencontainers.image.description="Offline static email triage; no URL/IP following or attachment execution" \
      org.opencontainers.image.source="https://github.com/thatirguy/threadsaw" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="MIT"

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
