# Modelo de concorrência e regiões críticas (Fase 2)

Documento exigido pela entrega 3 da Fase 2. Explica como o proxy MITM
(`proxy/proxy_mitm.py`) atende várias sessões ao mesmo tempo e quais são as
regiões críticas (estado compartilhado entre threads) e como elas são
protegidas. O servidor (`servico_alvo/servidor.py`) também ficou concorrente e
é descrito no fim.

## 1. Modelo de concorrência do proxy

O proxy usa **uma thread por conexão aceita** e, dentro de cada sessão, **duas
threads de relay**, uma para cada sentido:

```
accept() ─▶ thread tratar_sessao (1 por cliente)
                 │ conecta no servidor real
                 ├─▶ thread relay  C->S   (cliente  → servidor)
                 └─▶ thread relay  S->C   (servidor → cliente)
```

Por que duas threads por sessão: o relay é bidirecional e cada sentido fica
**bloqueado em leitura** (`recv`) esperando dados. Se um único fluxo de
execução tentasse cuidar dos dois sentidos, a espera por um lado travaria o
outro. Com uma thread por sentido, cada direção avança de forma independente.

Ciclo de vida de uma sessão (`tratar_sessao`): recebe o socket do cliente,
abre o socket para o servidor, sobe as duas threads de relay, faz `join` nas
duas e encerra. Quando qualquer um dos lados fecha, a função `relay` fecha os
**dois** sockets daquela sessão (`shutdown` + `close`), o que desbloqueia a
thread do outro sentido e encerra a sessão por inteiro.

As threads são `daemon`: o `Ctrl+C` no proxy derruba tudo sem travar.

## 2. Robustez (isolamento entre sessões)

Cada sessão tem seus próprios sockets e seu próprio par de threads. Nada do
caminho de dados é compartilhado entre sessões. Por isso:

- Uma **desconexão abrupta** vira `ConnectionError`/`OSError`, capturada dentro
  de `relay`; só aquela sessão termina, as outras seguem.
- **Linhas malformadas** (bytes inválidos em UTF-8 ou sem o terminador `\n`)
  são **repassadas intactas**, sem tentativa de modificação, e nunca derrubam a
  thread (o `decode` usa tratamento de erro e cada regra roda dentro de
  `try/except`).

Isso foi testado: um cliente que envia lixo binário e desconecta no meio roda
**em paralelo** com um cliente normal, e o normal conclui sem ser afetado (ver
`docs/capturas/fase2_robustez_cliente.txt` e `docs/capturas/fase2_proxy_log.txt`).

## 3. Regiões críticas do proxy e sua proteção

Estado compartilhado entre todas as threads e o lock que o protege:

| Estado compartilhado | O que é | Proteção |
|----------------------|---------|----------|
| `_sid` | contador que dá um número único a cada sessão | `_sid_lock` |
| `_stats` | totais globais (sessões, linhas, linhas modificadas) | `_stats_lock` |
| saída padrão (log) | `print` chamado por várias threads | `LOG_LOCK` |
| `REGRAS` | lista de regras de modificação | imutável, só leitura — **sem lock** |

Por que o lock é necessário nas três primeiras: são operações **compostas**
(ler, alterar e gravar de volta). Por exemplo, `_sid += 1` é, na prática, ler o
valor, somar e escrever. Sem exclusão mútua, duas sessões concorrentes poderiam
ler o mesmo valor e receber **ids iguais**. O mesmo vale para somar em
`_stats`. No log, sem o `LOG_LOCK` as linhas de threads diferentes se
intercalariam no meio de uma mensagem, embaralhando a saída.

O GIL do CPython **não** resolve isso: ele serializa bytecode, mas não garante
que uma sequência ler-modificar-escrever rode sem interrupção. Por isso os
locks são explícitos.

`REGRAS` é lida mas nunca alterada em tempo de execução, então pode ser
compartilhada sem lock.

## 4. Garantias de ordem

Dentro de **um sentido**, a ordem das mensagens é preservada: há uma só thread
por sentido e o TCP entrega em ordem. **Entre** os dois sentidos não há ordem
garantida — o que é esperado num intermediário, pois cliente e servidor falam
de forma assíncrona.

## 5. Concorrência no servidor

O servidor (`servico_alvo/servidor.py`) também virou concorrente: **uma thread
por conexão**. O repositório chave-valor passou a ser **compartilhado** entre as
sessões, então ele é a região crítica do servidor:

| Estado compartilhado | Proteção |
|----------------------|----------|
| `REPOSITORIO` (dict chave→valor) | `REPO_LOCK` nos comandos `SET`, `GET`, `DEL`, `LIST` |
| saída padrão (log) | `LOG_LOCK` |

O estado de **autenticação** (`LOGIN`) é por conexão, guardado na pilha da
própria thread, e por isso não precisa de lock.
