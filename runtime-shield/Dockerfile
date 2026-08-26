# Runtime Shield — minimal, non-root, production image.
FROM python:3.12-slim AS build

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY shield ./shield
RUN pip install --no-cache-dir --upgrade pip build \
 && python -m build --wheel --outdir /dist


FROM python:3.12-slim

LABEL org.opencontainers.image.title="Runtime Shield" \
      org.opencontainers.image.description="Runtime security for AI agents" \
      org.opencontainers.image.licenses="Apache-2.0"

# Run as an unprivileged user: the shield should never be the most
# privileged thing in the deployment.
RUN useradd --create-home --uid 10001 shield

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl "runtime-shield[server,sign]" \
 && rm -rf /tmp/*.whl

WORKDIR /app
RUN chown shield:shield /app
USER shield

# Config and audit log live on a mounted volume, not in the image.
VOLUME ["/app/data"]
ENV SHIELD_HOST=0.0.0.0 \
    SHIELD_PORT=8000 \
    SHIELD_AUDIT_PATH=/app/data/shield-audit.jsonl \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2).status==200 else 1)"

ENTRYPOINT ["shield"]
CMD ["serve"]
