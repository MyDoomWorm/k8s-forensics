FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    cmake ninja-build libssl-dev git gcc g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --upgrade pip && \
    pip install kubernetes requests cryptography

RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python /tmp/liboqs-python && \
    cd /tmp/liboqs-python && pip install . && \
    rm -rf /tmp/liboqs-python

COPY agent/ /app/agent/

ENV FORENSICS_DB=/data/forensics.db
ENV FORENSICS_KEY=/data/forensics_key.bin
ENV FORENSICS_NAMESPACE=default
ENV FORENSICS_INTERVAL=30

RUN mkdir -p /data
RUN python3 -c "import oqs; print('liboqs OK')"

CMD ["python3", "/app/agent/collector.py"]
