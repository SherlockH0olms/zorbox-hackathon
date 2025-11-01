@"
FROM ubuntu:22.04

# build tools + yara dev (yara-python üçün lazım ola bilər) + strace/firejail
RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    python3-pip \
    python3-dev \
    libssl-dev \
    libffi-dev \
    libyara-dev \
    yara \
    strace \
    ltrace \
    firejail \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --upgrade pip && pip3 install -r /tmp/requirements.txt

COPY native_engine.py /app/native_engine.py
WORKDIR /app

ENTRYPOINT ["python3", "native_engine.py"]
"@ > Dockerfile