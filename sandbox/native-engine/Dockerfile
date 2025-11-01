FROM ubuntu:22.04

# Tarih kontrolünü tamamen kapat (her satırda)
RUN apt-get update -o Acquire::Check-Valid-Until=false -o Acquire::Check-Date=false && \
    apt-get install -y -o Acquire::Check-Valid-Until=false \
    python3 python3-pip build-essential libmagic1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements_minimal.txt requirements.txt
RUN pip3 install --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

COPY native_engine.py .

RUN python3 -c "import pefile, psutil, colorlog; print('OK')"

ENTRYPOINT ["python3", "native_engine.py"]