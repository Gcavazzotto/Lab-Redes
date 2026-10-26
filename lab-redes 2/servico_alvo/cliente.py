#!/usr/bin/env python3
"""
Cliente do protocolo KVP (Key-Value Protocol) - Fase 1.

Conecta ao servidor alvo por TCP e fala o protocolo em texto claro.
Dois modos:

  - Interativo (padrao): digite comandos KVP, veja as respostas.
  - Demo (--demo): executa um roteiro fixo (LOGIN + SET + GET + LIST),
    util para gerar trafego reproduzivel enquanto o sniffer e o Wireshark
    capturam. Esse roteiro envia credenciais e valores sensiveis em texto
    claro, exatamente o que a Fase 1 quer evidenciar.

Uso:
    python3 cliente.py --host <ip-do-servidor> [--port 5050]
    python3 cliente.py --host <ip-do-servidor> --demo
"""
import argparse
import socket
import sys
import time

import protocolo


def ler_resposta(arquivo) -> str:
    linha = arquivo.readline()
    if not linha:
        return ""
    return linha.decode(protocolo.ENCODING, errors="replace").strip()


def enviar(conexao, arquivo, comando: str, pausa: float = 0.0) -> str:
    """Envia um comando e retorna a resposta do servidor."""
    conexao.sendall(protocolo.codificar(comando))
    resposta = ler_resposta(arquivo)
    print(f">> {comando}")
    print(f"<< {resposta}")
    if pausa:
        time.sleep(pausa)
    return resposta


def rodar_demo(conexao, arquivo) -> None:
    """Roteiro fixo que gera trafego sensivel para captura."""
    print("[*] Modo demo: gerando trafego em texto claro para captura.\n")
    ler_resposta(arquivo)  # consome o banner "OK KVP servidor pronto"
    enviar(conexao, arquivo, "PING", pausa=0.3)
    enviar(conexao, arquivo, "LOGIN admin s3nh4-pucrs", pausa=0.3)
    enviar(conexao, arquivo, "SET cartao 4111-1111-1111-1111", pausa=0.3)
    enviar(conexao, arquivo, "SET cofre senha-do-cofre-123", pausa=0.3)
    enviar(conexao, arquivo, "GET cartao", pausa=0.3)
    enviar(conexao, arquivo, "LIST", pausa=0.3)
    enviar(conexao, arquivo, "QUIT", pausa=0.3)
    print("\n[*] Demo concluida. Todo o conteudo acima trafegou legivel.")


def rodar_demo_fase2(conexao, arquivo) -> None:
    """Roteiro da Fase 2: dispara as modificacoes do proxy MITM.

    O cliente nao sabe que fala com um proxy. Ele acha que aponta para o
    servidor. As respostas mostram o conteudo adulterado sendo aceito."""
    print("[*] Modo demo Fase 2: trafego que o proxy MITM vai adulterar.\n")
    ler_resposta(arquivo)  # consome o banner "OK KVP servidor pronto"
    enviar(conexao, arquivo, "LOGIN admin s3nh4-pucrs", pausa=0.3)
    # 1) Valor que o cliente grava achando que e o proprio destino.
    enviar(conexao, arquivo, "SET destino conta-do-bernardo", pausa=0.3)
    # 2) O cliente confere e ve que o servidor guardou OUTRA coisa (C->S alterado).
    enviar(conexao, arquivo, "GET destino", pausa=0.3)
    # 3) O cliente pergunta o saldo real...
    enviar(conexao, arquivo, "SET saldo 100", pausa=0.3)
    # 4) ...e recebe um saldo inflado pelo proxy (S->C alterado).
    enviar(conexao, arquivo, "GET saldo", pausa=0.3)
    enviar(conexao, arquivo, "QUIT", pausa=0.3)
    print("\n[*] Demo Fase 2 concluida. Compare o que foi enviado com o que voltou.")


def rodar_interativo(conexao, arquivo) -> None:
    print("[*] Modo interativo. Comandos: LOGIN, SET, GET, DEL, LIST, PING, QUIT.")
    print(f"[*] Banner: {ler_resposta(arquivo)}")
    try:
        while True:
            try:
                comando = input("kvp> ").strip()
            except EOFError:
                comando = "QUIT"
            if not comando:
                continue
            conexao.sendall(protocolo.codificar(comando))
            resposta = ler_resposta(arquivo)
            print(resposta)
            if comando.upper().startswith("QUIT") or not resposta:
                break
    except KeyboardInterrupt:
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Cliente KVP (texto claro) - Fase 1")
    parser.add_argument("--host", required=True, help="IP/host do servidor")
    parser.add_argument("--port", type=int, default=protocolo.PORTA_PADRAO, help="porta TCP")
    parser.add_argument("--demo", action="store_true", help="roteiro da Fase 1 (trafego em texto claro)")
    parser.add_argument("--demo-fase2", action="store_true", help="roteiro da Fase 2 (aciona o proxy MITM)")
    args = parser.parse_args()

    try:
        conexao = socket.create_connection((args.host, args.port), timeout=10)
    except OSError as erro:
        print(f"[!] Nao foi possivel conectar em {args.host}:{args.port}: {erro}")
        sys.exit(1)

    print(f"[*] Conectado em {args.host}:{args.port}")
    arquivo = conexao.makefile("rb", buffering=0)
    try:
        if args.demo_fase2:
            rodar_demo_fase2(conexao, arquivo)
        elif args.demo:
            rodar_demo(conexao, arquivo)
        else:
            rodar_interativo(conexao, arquivo)
    finally:
        arquivo.close()
        conexao.close()


if __name__ == "__main__":
    main()
