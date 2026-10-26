#!/usr/bin/env bash
# Executa a demonstracao da Fase 2 em nos isolados (contêineres) e coleta a
# evidencia de uma UNICA corrida consistente:
#   - captura pcap no trecho cliente<->proxy  (no cliente)
#   - captura pcap no trecho proxy<->servidor (no servidor)
#   - saida do sniffer proprio (extracao de campos) no trecho do cliente
#   - log do proxy (leitura + modificacao + concorrencia)
#
# Uso:  bash run_demo.sh
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p capturas
rm -f capturas/*.pcap capturas/*.txt 2>/dev/null || true

espera() { python3 -c "import time;time.sleep($1)"; }

echo "==> subindo os nos (build na primeira vez)"
docker compose up -d --build

echo "==> esperando o proxy ficar pronto"
for _ in $(seq 1 60); do
  if docker logs kvp-proxy 2>&1 | grep -q "escutando"; then break; fi
  espera 0.5
done
docker logs kvp-servidor 2>&1 | grep -q "escutando" || true

echo "==> iniciando capturas (tcpdump nos dois trechos + sniffer no cliente)"
docker exec -d kvp-cliente  sh -c 'tcpdump -i eth0 -U -w /cap/leg_cliente.pcap  tcp port 5050 & echo $! > /cap/tcp_cli.pid'
docker exec -d kvp-servidor sh -c 'tcpdump -i eth0 -U -w /cap/leg_servidor.pcap tcp port 5050 & echo $! > /cap/tcp_srv.pid'
docker exec -d kvp-cliente  sh -c 'python3 -u /app/sniffer/sniffer.py --iface eth0 --port 5050 > /cap/sniffer_cliente.txt 2>&1 & echo $! > /cap/snf_cli.pid'
espera 2   # deixa as capturas inicializarem antes do trafego

echo "==> CENARIO PRINCIPAL: cliente -> proxy -> servidor (com modificacao)"
docker exec kvp-cliente python3 /app/servico_alvo/cliente.py \
    --host 10.10.0.20 --port 5050 --demo-fase2 | tee capturas/cliente_saida.txt
espera 1

echo "==> ROBUSTEZ: cliente malformado em paralelo com um cliente normal"
# cliente normal (em segundo plano) deve concluir mesmo com lixo em outra sessao
docker exec kvp-cliente python3 /app/servico_alvo/cliente.py \
    --host 10.10.0.20 --port 5050 --demo-fase2 > capturas/cliente_robustez.txt 2>&1 &
NORMAL=$!
# sessao malformada: bytes invalidos, sem terminador, e desconexao abrupta
docker exec kvp-cliente python3 -c "
import socket
s = socket.create_connection(('10.10.0.20', 5050))
s.sendall(b'\xff\xff\x00 lixo binario sem newline')
s.close()
" || true
wait $NORMAL && echo "   cliente normal concluiu apesar da sessao malformada"
espera 1

echo "==> CONCORRENCIA: 3 clientes simultaneos pelo proxy"
for i in 1 2 3; do
  docker exec kvp-cliente python3 /app/servico_alvo/cliente.py \
      --host 10.10.0.20 --port 5050 --demo-fase2 > "capturas/cliente_conc_$i.txt" 2>&1 &
done
wait
echo "   os 3 clientes concluiram"
espera 1

echo "==> encerrando capturas e coletando logs"
docker exec kvp-cliente  sh -c 'kill -INT $(cat /cap/tcp_cli.pid) $(cat /cap/snf_cli.pid)' 2>/dev/null || true
docker exec kvp-servidor sh -c 'kill -INT $(cat /cap/tcp_srv.pid)' 2>/dev/null || true
espera 1
rm -f capturas/*.pid 2>/dev/null || true
docker logs kvp-proxy    > capturas/proxy_log.txt 2>&1
docker logs kvp-servidor > capturas/servidor_log.txt 2>&1

echo "==> baixando os nos"
docker compose down >/dev/null 2>&1

echo "==> evidencias geradas em deploy/capturas:"
ls -l capturas
