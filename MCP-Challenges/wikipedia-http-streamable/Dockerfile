# Challenge 7: The Wikipedia Cache

FROM python:3.11-slim

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*
WORKDIR /app

RUN pip install --no-cache-dir mcp httpx uvicorn

COPY . .

RUN useradd -m ctf
RUN chown -R ctf:ctf /app
USER ctf

ENV CTF_FLAG=CTF{p4th_tr4v3rs4l_w1k1_c4ch3}
EXPOSE 1337

ENTRYPOINT ["/bin/sh", "-c", "socat TCP-LISTEN:1337,reuseaddr,fork EXEC:'python3 wikipedia-mcp.py'"]
