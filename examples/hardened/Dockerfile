FROM python:3.12-slim@sha256:2b0079146a74e23bf4ae8f6a28e1b484c6292f6fb904cbb51825b4a19812fcd8
WORKDIR /app
COPY app /app
RUN useradd --uid 10001 --no-create-home shop
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/')"
CMD ["python", "-m", "http.server", "8080"]
