FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.source="https://github.com/r4venrudy/RudyNET" org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt && python -m pip check
COPY rudynet.py rudysec.py raven.png LICENSE ./
COPY modules ./modules
COPY utils ./utils
COPY data ./data
COPY tests ./tests
RUN python -m unittest discover -s tests -v && useradd --uid 10001 --create-home rudy && mkdir /data && chown rudy:rudy /data
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "/app/rudynet.py"]
CMD ["--help"]
