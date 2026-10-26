# Interceptação e defesa de um protocolo de aplicação

Laboratório de Redes de Computadores (PUCRS). Serviço alvo em texto claro (KVP),
um sniffer passivo (Fase 1) e um proxy MITM concorrente (Fase 2).

- Fase 1: serviço alvo + sniffer que lê o tráfego (quebra de confidencialidade).
- Fase 2: proxy MITM que lê e altera mensagens em trânsito (quebra de
  integridade e autenticação), atendendo várias sessões ao mesmo tempo.

## Estrutura

```
lab-redes/
├── servico_alvo/
│   ├── protocolo.py        # definição do protocolo KVP e credenciais do lab
│   ├── servidor.py         # servidor concorrente (uma thread por conexão)
│   └── cliente.py          # cliente; --demo (Fase 1) e --demo-fase2 (Fase 2)
├── proxy/
│   └── proxy_mitm.py       # proxy MITM concorrente (Fase 2)
├── sniffer/
│   └── sniffer.py          # sniffer raw socket: remonta e extrai campos do KVP
├── deploy/
│   ├── Dockerfile          # imagem dos nós (Python + tcpdump)
│   ├── docker-compose.yml  # nós isolados: cliente, proxy, servidor
│   └── run_demo.sh         # executa a demo da Fase 2 e coleta as evidências
├── docs/
│   ├── RELATORIO.pdf        # relatório da Fase 1
│   ├── RELATORIO.tex
│   ├── RELATORIO_FASE2.pdf  # relatório da Fase 2
│   ├── RELATORIO_FASE2.tex
│   ├── CONCORRENCIA.md      # modelo de concorrência e regiões críticas (Fase 2)
│   └── capturas/            # pcaps, prints e logs usados nos relatórios
└── trabalho_lab_redes.pdf
```

## O protocolo KVP

Orientado a linha, UTF-8, uma mensagem por linha terminada em `\n`, sobre TCP na
porta 5050. Sem cifragem e sem hash de senha: tudo trafega legível. Comandos do
cliente: `LOGIN <usuario> <senha>`, `SET <chave> <valor>`, `GET <chave>`,
`DEL <chave>`, `LIST`, `PING`, `QUIT`. Respostas do servidor: `OK ...`,
`VALUE <chave> <valor>`, `KEYS ...`, `ERR <motivo>`, `BYE`.

Credenciais de teste, só para o laboratório: `admin / s3nh4-pucrs`.

## Topologia

Fase 1 (escuta passiva), três nós no mesmo segmento:

```
  cliente ───────▶ servidor        observador (sniffer)
                                    lê os quadros do segmento
```

Fase 2 (redirecionamento para o proxy). O cliente é configurado para apontar
para o proxy; o proxy abre a conexão real ao servidor e faz o relay:

```
  cliente ──▶ proxy MITM ──▶ servidor
 10.10.0.30   10.10.0.20     10.10.0.10
            (lê e altera
             as mensagens)
```

O redirecionamento é por configuração do cliente: basta apontar o `--host` do
cliente para o IP do proxy em vez do servidor.

## Como executar a Fase 2 em nós isolados (Docker)

Os nós são contêineres com IPs distintos numa rede bridge (`10.10.0.0/24`). O
tráfego entre eles passa por Ethernet real, não por loopback. É a forma
reproduzível de rodar a demonstração e coletar as evidências:

```bash
cd deploy
bash run_demo.sh
```

O script sobe os três nós, aponta o cliente para o proxy, executa o cenário
principal, um teste de robustez e um teste de concorrência (3 clientes
simultâneos), e grava as evidências em `deploy/capturas/`:

- `leg_cliente.pcap` e `leg_servidor.pcap`: captura dos dois trechos;
- `proxy_log.txt`: leitura e modificação feitas pelo proxy;
- `sniffer_cliente.txt`: saída do sniffer próprio.

Para subir os nós e usar manualmente:

```bash
cd deploy
docker compose up -d --build
docker exec -it kvp-cliente python3 /app/servico_alvo/cliente.py --host 10.10.0.20 --demo-fase2
docker compose down
```

## Como executar em VMs separadas

O mesmo código roda sem Docker. Use três VMs (ou quatro, com observador) no
mesmo segmento isolado, com Python 3.8+:

```bash
# VM-servidor
cd servico_alvo && python3 servidor.py --host 0.0.0.0 --port 5050

# VM-proxy  (encaminha para o IP do servidor)
cd proxy && python3 proxy_mitm.py --listen 0.0.0.0:5050 --server <IP-SERVIDOR>:5050

# VM-cliente  (aponta para o IP do PROXY)
cd servico_alvo && python3 cliente.py --host <IP-PROXY> --port 5050 --demo-fase2
```

Sniffer passivo da Fase 1 (precisa de Linux e root, pois usa socket raw):

```bash
sudo python3 sniffer/sniffer.py --iface eth0 --port 5050
```

## O que a Fase 2 demonstra

Rodando o cliente pelo proxy, duas mensagens são alteradas em trânsito sem que
as pontas percebam:

- `SET destino conta-do-bernardo` (do cliente) chega ao servidor como
  `SET destino conta-do-atacante`;
- a resposta `VALUE saldo 100` (do servidor) chega ao cliente como
  `VALUE saldo 999999`.

Comparando a captura dos dois trechos (cliente↔proxy e proxy↔servidor) vê-se a
diferença. Sem integridade nem autenticação, o conteúdo é adulterado sem
detecção. A defesa vem na Fase 3 (TLS e autenticação). Detalhes e evidências em
`docs/RELATORIO_FASE2.pdf`; o modelo de concorrência em `docs/CONCORRENCIA.md`.
