ARG PYTHON_BASE_IMAGE=python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
ARG GRYPE_IMAGE=anchore/grype:v0.109.1@sha256:5db068d57d48ee251726e6e2d4903f47a909371ed83b96ee4812d84a10288c65
ARG CYCLONEDX_CLI_IMAGE=cyclonedx/cyclonedx-cli:0.30.0@sha256:8475ecf6c09d17dbb3b039d6999334d3ecf3aaed13395b3413007e568d52a9e3
ARG KODA_GRYPE_IMAGE=anchore/grype:v0.115.0@sha256:decd87500a90c1e4faa1706f77b0b2cbc1d2f9364e976f1898ce9037de09cc3a
FROM ${KODA_GRYPE_IMAGE} AS koda_grype
FROM ${GRYPE_IMAGE} AS grype
FROM ${CYCLONEDX_CLI_IMAGE} AS cyclonedx
FROM ${PYTHON_BASE_IMAGE}
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
WORKDIR /app
COPY apps/api/pyproject.toml ./
COPY apps/api/koda_tracker ./koda_tracker
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=koda_grype /grype /usr/local/bin/koda-grype
COPY --from=cyclonedx /cyclonedx /usr/local/bin/cyclonedx
RUN pip install --no-cache-dir ".[postgres]"
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/koda-sbom-tracker/
RUN addgroup --system tracker && adduser --system --ingroup tracker tracker \
    && mkdir -p /var/lib/sbom-tracker/data-updates /var/lib/sbom-tracker/artifacts /var/lib/sbom-tracker/vuln-data \
    && chown -R tracker:tracker /var/lib/sbom-tracker
USER tracker
EXPOSE 8000
CMD ["uvicorn", "koda_tracker.main:app", "--host", "0.0.0.0", "--port", "8000"]
