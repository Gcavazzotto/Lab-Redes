#!/usr/bin/env python3
"""
Servidor do protocolo KVP (Key-Value Protocol).

Servico alvo do laboratorio: um repositorio chave-valor com login, falando
um protocolo de aplicacao EM TEXTO CLARO sobre TCP (sockets diretos, sem
framework que esconda o socket).

Fase 2: o servidor passou a ser CONCORRENTE (uma thread por conexao) e o
repositorio chave-valor agora e COMPARTILHADO entre as sessoes, protegido
por um lock. Isso permite que varias sessoes (inclusive varias passando pelo
proxy MITM) sejam atendidas ao mesmo tempo.

Uso:
    python3 servidor.py [--host 0.0.0.0] [--port 5050]
"""
import argparse
import socket
import threading

import protocolo

# ---------------------------------------------------------------------------
# Estado compartilhado entre as threads de conexao.
#   REPOSITORIO: o repositorio chave-valor, visivel por todas as sessoes.
#   REPO_LOCK  : protege leituras/escritas no REPOSITORIO (regiao critica).
#   LOG_LOCK   : serializa os prints para o log nao sair embaralhado.
# ---------------------------------------------------------------------------
REPOSITORIO = {}
REPO_LOCK = threading.Lock()
LOG_LOCK = threading.Lock()


def log(mensagem: str) -> None:
    """Escreve no stdout de forma atomica (varias threads escrevem aqui)."""
    with LOG_LOCK:
        print(mensagem, flush=True)


def tratar_cliente(conexao: socket.socket, endereco) -> None:
    """Atende uma sessao KVP ate o cliente encerrar. Roda em sua propria thread."""
    peer = f"{endereco[0]}:{endereco[1]}"
    log(f"[+] Conexao de {peer}")
    # Estado da SESSAO (por conexao): autenticacao nao e compartilhada.
    sessao = {"autenticado": False, "usuario": None}

    arquivo = conexao.makefile("rwb", buffering=0)
    try:
        conexao.sendall(protocolo.codificar("OK KVP servidor pronto"))
        for linha_bruta in arquivo:
            linha = linha_bruta.decode(protocolo.ENCODING, errors="replace").strip()
            if not linha:
                continue
            log(f"    <- {peer}: {linha}")

            partes = linha.split(" ")
            comando = partes[0].upper()
            resposta = processar_comando(comando, partes, sessao)

            log(f"    -> {peer}: {resposta}")
            conexao.sendall(protocolo.codificar(resposta))

            if comando == "QUIT":
                break
    except (ConnectionError, OSError):
        log(f"[!] Conexao com {peer} caiu")
    finally:
        arquivo.close()
        conexao.close()
        log(f"[-] Encerrada {peer}")


def processar_comando(comando: str, partes: list, sessao: dict) -> str:
    """Executa um comando KVP e retorna a linha de resposta.

    `sessao` guarda o estado de autenticacao desta conexao. O repositorio e
    global e so e tocado dentro de REPO_LOCK.
    """
    if comando == "PING":
        return "OK pong"

    if comando == "LOGIN":
        if len(partes) < 3:
            return "ERR uso: LOGIN <usuario> <senha>"
        usuario, senha = partes[1], partes[2]
        # Credenciais comparadas em texto claro - trafegaram legiveis no fio.
        if protocolo.USUARIOS.get(usuario) == senha:
            sessao["autenticado"] = True
            sessao["usuario"] = usuario
            return f"OK logado como {usuario}"
        return "ERR credenciais invalidas"

    if comando == "QUIT":
        return "BYE"

    # Daqui em diante exige sessao autenticada.
    if not sessao["autenticado"]:
        return "ERR faca LOGIN primeiro"

    if comando == "SET":
        if len(partes) < 3:
            return "ERR uso: SET <chave> <valor>"
        chave = partes[1]
        valor = " ".join(partes[2:])
        with REPO_LOCK:  # regiao critica: escrita no repositorio compartilhado
            REPOSITORIO[chave] = valor
        return f"OK gravado {chave}"

    if comando == "GET":
        if len(partes) < 2:
            return "ERR uso: GET <chave>"
        chave = partes[1]
        with REPO_LOCK:  # regiao critica: leitura do repositorio compartilhado
            valor = REPOSITORIO.get(chave)
        if valor is not None:
            return f"VALUE {chave} {valor}"
        return "ERR chave nao encontrada"

    if comando == "DEL":
        if len(partes) < 2:
            return "ERR uso: DEL <chave>"
        chave = partes[1]
        with REPO_LOCK:  # regiao critica: remocao no repositorio compartilhado
            removido = REPOSITORIO.pop(chave, None)
        return f"OK removido {chave}" if removido is not None else "ERR chave nao encontrada"

    if comando == "LIST":
        with REPO_LOCK:  # regiao critica: snapshot das chaves
            chaves = sorted(REPOSITORIO)
        return "KEYS " + " ".join(chaves) if chaves else "KEYS"

    return f"ERR comando desconhecido: {comando}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor KVP concorrente (texto claro)")
    parser.add_argument("--host", default="0.0.0.0", help="endereco de escuta")
    parser.add_argument("--port", type=int, default=protocolo.PORTA_PADRAO, help="porta TCP")
    args = parser.parse_args()

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((args.host, args.port))
    servidor.listen(16)
    log(f"[*] Servidor KVP concorrente escutando em {args.host}:{args.port} (texto claro)")
    log("[*] Pressione Ctrl+C para encerrar.")

    try:
        while True:
            conexao, endereco = servidor.accept()
            # Uma thread por conexao: varias sessoes ao mesmo tempo.
            t = threading.Thread(target=tratar_cliente, args=(conexao, endereco), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("\n[*] Encerrando servidor.")
    finally:
        servidor.close()


if __name__ == "__main__":
    main()
