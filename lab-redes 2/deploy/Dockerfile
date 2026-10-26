# Imagem unica usada pelos nos do laboratorio (cliente, servidor, proxy).
# Base enxuta com Python e tcpdump (para capturar a evidencia em cada no).
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# O codigo e montado em /app por volume (docker-compose), mantendo uma unica
# fonte de verdade. Nada e copiado para a imagem.
