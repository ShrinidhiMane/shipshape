FROM python:latest
ENV DB_PASSWORD=Sup3rS3cretPassw0rd
ADD https://example.com/tools/healthcheck.tar.gz /opt/
RUN curl -fsSL https://example.com/install.sh | sh
COPY app /app
WORKDIR /app
CMD ["python", "-m", "http.server", "8080"]
