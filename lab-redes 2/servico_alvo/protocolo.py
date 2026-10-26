"""
Definicao do protocolo KVP (Key-Value Protocol) - Fase 1.

Protocolo de aplicacao proprio, INSEGURO POR DESIGN (texto claro, sem
cifragem e sem integridade), criado para o laboratorio de Redes.

Caracteristicas:
  - Transporte: TCP.
  - Codificacao: UTF-8, orientado a linha, cada mensagem terminada em '\\n'.
  - Sem TLS, sem hash de senha, sem assinatura: tudo trafega legivel.

O proposito desta fragilidade e didatico: na Fase 1 o sniffer passivo le as
credenciais e os valores direto do fio; na Fase 3 o canal sera protegido.

Comandos do cliente (um por linha):
  LOGIN <usuario> <senha>   -> autentica a sessao (credenciais em texto claro)
  SET <chave> <valor>       -> grava um valor (requer login)
  GET <chave>               -> le um valor (requer login)
  DEL <chave>               -> remove um valor (requer login)
  LIST                      -> lista as chaves (requer login)
  PING                      -> teste de conectividade
  QUIT                      -> encerra a sessao

Respostas do servidor (um por linha):
  OK <texto>
  VALUE <chave> <valor>
  KEYS <chave1> <chave2> ...
  ERR <motivo>
  BYE
"""

PORTA_PADRAO = 5050
ENCODING = "utf-8"
TERMINADOR = "\n"

# Credenciais de exemplo embutidas no servidor (apenas para o laboratorio).
# Sao justamente o "segredo" que o sniffer da Fase 1 vai capturar legivel.
USUARIOS = {
    "admin": "s3nh4-pucrs",
    "bernardo": "lab-redes-2026",
}


def codificar(mensagem: str) -> bytes:
    """Serializa uma mensagem de aplicacao (adiciona terminador)."""
    return (mensagem + TERMINADOR).encode(ENCODING)
