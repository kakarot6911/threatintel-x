# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip build && python -m build --wheel --outdir /wheels

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    TIX_DATA_DIR=/app/data TIX_CONFIG_DIR=/app/config \
    TIX_DATABASE_URL=sqlite:////var/lib/threatintel/threatintel.db
RUN groupadd --system tix && useradd --system --gid tix --home /app --shell /usr/sbin/nologin tix \
    && mkdir -p /var/lib/threatintel && chown tix:tix /var/lib/threatintel
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
COPY --chown=tix:tix config ./config
COPY --chown=tix:tix data/attack ./data/attack
COPY --chown=tix:tix data/reference ./data/reference
COPY --chown=tix:tix data/synthetic ./data/synthetic
USER tix
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"
CMD ["threatintel", "serve", "--host", "0.0.0.0", "--port", "8000"]
