#!/usr/bin/env python3
"""
Interceptador passivo (sniffer de aplicacao) - KVP.

Le o trafego da rede com um SOCKET RAW e reconstroi o protocolo KVP em texto
claro. Demonstra a quebra de CONFIDENCIALIDADE: o sniffer nao conversa com
ninguem, so observa o fio, e mesmo assim enxerga tudo.

Nao usa biblioteca de captura pronta (scapy etc.): abre um AF_PACKET/SOCK_RAW
e faz o parsing manual de Ethernet -> IPv4 -> TCP -> payload.

Melhorias em relacao a primeira versao:
  - REMONTAGEM por fluxo: junta os bytes de cada conexao TCP e so processa
    mensagens completas (terminadas em '\\n'), mesmo que uma mensagem venha
    partida em varios pacotes ou varias mensagens cheguem juntas.
  - EXTRACAO DE CAMPOS: nao so marca a linha, mas separa comando, chave,
    valor, usuario e senha, destacando os campos sensiveis.

Requisitos:
  - Linux (AF_PACKET). Rode com sudo (socket raw).

Uso:
    sudo python3 sniffer.py [--iface eth0] [--port 5050]
"""
import argparse
import socket
import struct
import sys

ETH_P_ALL = 0x0003
ETHERTYPE_IPV4 = 0x0800
IPPROTO_TCP = 6


def parse_ethernet(quadro: bytes):
    """Retorna (ethertype, payload) ou (None, None) se curto demais."""
    if len(quadro) < 14:
        return None, None
    _dst, _src, ethertype = struct.unpack("!6s6sH", quadro[:14])
    return ethertype, quadro[14:]


def parse_ipv4(pacote: bytes):
    """Retorna (protocolo, ip_origem, ip_destino, payload) ou None."""
    if len(pacote) < 20:
        return None
    primeiro_byte = pacote[0]
    if (primeiro_byte >> 4) != 4:
        return None
    ihl = (primeiro_byte & 0x0F) * 4  # tamanho do cabecalho IP em bytes
    if len(pacote) < ihl:
        return None
    protocolo = pacote[9]
    ip_origem = socket.inet_ntoa(pacote[12:16])
    ip_destino = socket.inet_ntoa(pacote[16:20])
    return protocolo, ip_origem, ip_destino, pacote[ihl:]


def parse_tcp(segmento: bytes):
    """Retorna (porta_origem, porta_destino, seq, payload) ou None."""
    if len(segmento) < 20:
        return None
    porta_origem, porta_destino, seq, _ack = struct.unpack("!HHII", segmento[:12])
    data_offset = (segmento[12] >> 4) * 4  # tamanho do cabecalho TCP em bytes
    if len(segmento) < data_offset:
        return None
    return porta_origem, porta_destino, seq, segmento[data_offset:]


def extrair_campos(linha: str):
    """Separa a linha KVP em campos nomeados e marca os sensiveis.

    Retorna (descricao, sensivel: bool)."""
    partes = linha.split(" ")
    comando = partes[0].upper() if partes else ""

    if comando == "LOGIN" and len(partes) >= 3:
        return (f"LOGIN  usuario={partes[1]}  senha={partes[2]}", True)
    if comando == "SET" and len(partes) >= 3:
        return (f"SET    chave={partes[1]}  valor={' '.join(partes[2:])}", True)
    if comando == "GET" and len(partes) >= 2:
        return (f"GET    chave={partes[1]}", False)
    if comando == "DEL" and len(partes) >= 2:
        return (f"DEL    chave={partes[1]}", False)
    if comando == "VALUE" and len(partes) >= 3:
        return (f"VALUE  chave={partes[1]}  valor={' '.join(partes[2:])}", True)
    if comando == "KEYS":
        return (f"KEYS   chaves={partes[1:]}", False)
    if comando in ("OK", "ERR", "BYE", "PING"):
        return (f"{comando}  {' '.join(partes[1:])}".rstrip(), False)
    return (f"(linha nao-KVP) {linha}", False)


def processar_linhas(buffers: dict, chave_fluxo, dados: bytes):
    """Acrescenta `dados` ao buffer do fluxo e devolve as linhas completas.

    Remontagem: guarda o resto sem '\\n' para juntar com o proximo pacote."""
    buffer = buffers.get(chave_fluxo, b"") + dados
    linhas = []
    while b"\n" in buffer:
        bruta, buffer = buffer.split(b"\n", 1)
        linhas.append(bruta.decode("utf-8", errors="replace").rstrip("\r"))
    buffers[chave_fluxo] = buffer
    return linhas


def main() -> None:
    parser = argparse.ArgumentParser(description="Sniffer passivo KVP (socket raw)")
    parser.add_argument("--iface", default=None, help="interface (ex.: eth0). Padrao: todas")
    parser.add_argument("--port", type=int, default=5050, help="porta TCP do servico alvo")
    args = parser.parse_args()

    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except AttributeError:
        print("[!] AF_PACKET indisponivel: este sniffer precisa de Linux.")
        sys.exit(1)
    except PermissionError:
        print("[!] Permissao negada. Socket raw exige root: rode com sudo.")
        sys.exit(1)

    if args.iface:
        sniffer.bind((args.iface, 0))
        print(f"[*] Capturando na interface {args.iface}")
    else:
        print("[*] Capturando em todas as interfaces")
    print(f"[*] Filtrando TCP na porta {args.port} (protocolo KVP, texto claro)")
    print("[*] Ctrl+C para encerrar.\n")

    buffers = {}            # chave_fluxo -> bytes ainda nao terminados em \n
    total, mensagens = 0, 0
    try:
        while True:
            quadro = sniffer.recv(65535)
            total += 1

            ethertype, pacote_ip = parse_ethernet(quadro)
            if ethertype != ETHERTYPE_IPV4:
                continue
            res_ip = parse_ipv4(pacote_ip)
            if res_ip is None:
                continue
            protocolo_l4, ip_org, ip_dst, segmento = res_ip
            if protocolo_l4 != IPPROTO_TCP:
                continue
            res_tcp = parse_tcp(segmento)
            if res_tcp is None:
                continue
            porta_org, porta_dst, _seq, payload = res_tcp

            if args.port not in (porta_org, porta_dst):
                continue
            if not payload:
                continue  # pacote de controle (SYN/ACK) sem dados de aplicacao

            sentido = "CLIENTE->SERVIDOR" if porta_dst == args.port else "SERVIDOR->CLIENTE"
            chave_fluxo = (ip_org, porta_org, ip_dst, porta_dst)

            for linha in processar_linhas(buffers, chave_fluxo, payload):
                if not linha:
                    continue
                mensagens += 1
                descricao, sensivel = extrair_campos(linha)
                print("=" * 72)
                print(f"[#{mensagens}] {sentido}   {ip_org}:{porta_org} -> {ip_dst}:{porta_dst}")
                print(f"       campos: {descricao}")
                if sensivel:
                    print(f"  [!] SENSIVEL: {linha}")
    except KeyboardInterrupt:
        print(f"\n[*] Encerrando. {total} pacotes vistos, "
              f"{mensagens} mensagens KVP remontadas (porta {args.port}).")
    finally:
        sniffer.close()


if __name__ == "__main__":
    main()
