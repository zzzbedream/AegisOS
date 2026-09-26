# AegisOS

**Procedencia verificable para agentes que compran con x402 en Stellar.**

**Demo verificable:** https://aegisos-stellar.vercel.app

x402 prueba que el dinero se movió. No dice nada sobre si lo que llegó es lo que se pagó.
AegisOS decide si lo que un agente compró puede entrar en su memoria, respaldar una decisión
o desbloquear el siguiente pago.

> **Solo testnet.** Este repositorio no toca mainnet ni guarda claves privadas en el código.

---

## El problema

Stellar hizo baratos los micropagos por request: un agente puede comprar miles de veces al
día. Cada compra se vuelve contexto de la siguiente. Un vendedor hostil no necesita robar la
clave del agente: le basta con **vender datos envenenados** y dejar que el agente los use para
decidir su próximo pago.

| Capa | Pregunta | Quién la responde |
|---|---|---|
| Autorización | ¿*puede* el agente gastar? | mandatos / smart accounts (p. ej. REAPP) |
| Riel de gasto | ¿*cuánto* puede gastar? | límites, rate limits, allowlists |
| **Procedencia** | **¿puede confiar en lo que compró?** | **AegisOS** |

## El invariante

> Ningún contenido pagado puede convertirse en fundamento de un gasto posterior salvo que
> exista un **commitment previo**, un **binding verificable pago–entrega** y una
> **evaluación determinista de riesgo**.

## Cómo funciona

```
 agente                    signer aislado             vendedor x402         Soroban
   │  1. commitment firmado    │                           │                    │
   │  (qué compro, a quién,    │                           │                    │
   │   techo de monto)         │                           │                    │
   │── 2. petición tipada ────▶│ guard: ¿commitment de      │                    │
   │                           │ una clave de confianza?    │                    │
   │                           │ ¿destino, activo, monto    │                    │
   │                           │ cuadran? si no → DENIED    │                    │
   │◀── auth entry firmado ────│                           │                    │
   │── 3. pago x402 ─────────────────────────────────────▶│                    │
   │◀── 200 + contenido ──────────────────────────────────│                    │
   │  4. hash del contenido + evaluación de riesgo         │                    │
   │     → veredicto OK / TAINTED / MISMATCH / NOT_DELIVERED                   │
   │  5. receipt firmado ── cuarentena si no es OK                              │
   │── 6. excepciones: se anclan una a una, al instante ─────────────────────▶│
   │      OK: se agrupan en una raíz Merkle por vendedor ─────────────────────▶│
   │  7. el siguiente gasto que cite contenido en cuarentena → DENY            │
```

- **Signer aislado.** La clave del comprador vive en otro proceso del sistema operativo. El
  agente solo tiene un canal por el que pide operaciones tipadas; nunca «firma este blob».
  Si el auth entry no coincide con el commitment (otro destinatario, más monto, otro activo),
  el signer se niega **antes de firmar**, así que no se paga nada.
- **Commitment antes del pago.** Sin él, «entregaron otra cosa» no tiene significado.
- **Veredicto determinista.** Precedencia estricta `NOT_DELIVERED → MISMATCH → TAINTED → OK`.
  Detecta inyección de instrucciones en inglés y español, incluida la ofuscada con espacios o
  caracteres de ancho cero.
- **Corte de cascada.** El contenido `TAINTED` queda en cuarentena: `retrieve()` no lo
  devuelve, y un draft que lo cite se rechaza con `TAINTED_PROVENANCE_REQUIRES_OWNER`.
- **Anclaje público y barato.** Las excepciones (`TAINTED`, `MISMATCH`, `NOT_DELIVERED`) se
  anclan una a una, al instante. Las compras `OK` se agrupan en una raíz Merkle por vendedor,
  con hasta 1.024 compras en una transacción. Cualquiera puede verificar un receipt contra la
  clave publicada y contra la cadena, incluida su prueba de inclusión en el lote.

### Por qué agrupar

Medido en testnet el 24-sep-2026:

| Operación | Fee de red | Por compra |
|---|---|---|
| Liquidación x402 (la patrocina el facilitator) | 0,0023 XLM | 0,0023 XLM |
| Anclar un receipt suelto | 0,0714–0,1144 XLM | 0,0714–0,1144 XLM |
| **Anclar un lote de 1.024 receipts** | **0,0505 XLM** | **0,0000493 XLM** |

Anclar cada micropago cuesta más que el pago. En lote, anclar cuesta unas 47 veces menos que
liquidar.

## Demo en vivo: una compra real con las cuatro garantías

El 26-sep-2026 el agente le compró a un vendedor x402 **que no controlamos** (Stellar Bazaar,
servicio *Swap Risk Quote*, 0,001 USDC de testnet), pagando desde la smart account de AegisOS
y pidiendo la respuesta **a través de un attestor de Reclaim**. Un solo receipt demuestra:

| Garantía | Qué se probó | Evidencia |
|---|---|---|
| **C** · el pago es real y autorizado | La cuenta solo paga bajo un commitment firmado por la autoridad; notarizó el pago (seq 5) en la misma transacción | liquidación [`0aa433be…`](https://stellar.expert/explorer/testnet/tx/0aa433be6926461b607e89a8ed82be22c6929123eee1d01994a8475abc80b082) |
| **A + B** · contado una vez, sin omisiones | El registro recalculó la cadena de pagos de la cuenta hasta su cabeza y contó el veredicto él mismo | rango 5..5 [`d3039f4d…`](https://stellar.expert/explorer/testnet/tx/d3039f4d6b374cfafe91d7e0f6f0c8ec99307da389d708d554b44bc8919b9595) |
| **D** · el contenido vino del vendedor | El attestor de Reclaim `0x2448…9072` firmó la respuesta HTTP que vio por TLS, ligada al commitment de esta compra | prueba dentro del receipt |
| Receipt | Firmado por el attester publicado; veredicto `OK` | [`docs/evidence/2026-09-26-bazaar-reclaim/receipt.json`](docs/evidence/2026-09-26-bazaar-reclaim/receipt.json) |

Lo verifica cualquiera, sin secretos ni servicios de AegisOS o de Reclaim:

```bash
npm run verify:receipt -- docs/evidence/2026-09-26-bazaar-reclaim/receipt.json
```

Son 16 comprobaciones: firma del receipt, wasm de la cuenta, eslabón de la cadena, log de
pagos contra la cabeza on-chain, pertenencia al rango anclado, y las cinco de la prueba de
Reclaim (identificador, witness fijado en
[`testnet.json`](contracts/deployments/testnet.json), commitment, HTTP 200 y hash del cuerpo).

Un detalle que vale la pena: la respuesta probada incluye la cabecera `Payment-Response` del
vendedor, que dice `{"success":true, "payer":"CDUZ2FIO…", "transaction":"0aa433be…"}`. Es el
**propio vendedor**, por TLS y firmado por el attestor, confirmando que esta cuenta le pagó en
esa transacción. La firma de pago del comprador viajó en cabeceras privadas y no aparece en
la prueba.

**Límite de D:** el attestor tiene que poder llegar a la URL del vendedor, así que aplica a
vendedores públicos (como el Bazaar), no a los vendedores locales de `demo:attack`.

## Evidencia en testnet

| Qué | Dónde |
|---|---|
| Registro v3 (factory de cuentas, rangos verificados, lotes) | [`CBPGIT7F…U4NN`](https://stellar.expert/explorer/testnet/contract/CBPGIT7F2LU3PDDHWW7QIBEKVVDQVRME4WEUUHNU7YQLINZBR24IU4NN) · [contracts/deployments/testnet.json](contracts/deployments/testnet.json) |
| Smart account de la demo (creada por el factory) | [`CDUZ2FIO…APVZ`](https://stellar.expert/explorer/testnet/contract/CDUZ2FIOVNG25VU5ZGNCDT26C2N2LN5S24FJDHXEDXNY3JTIPAZJAPVZ) |
| Contrato v2 (histórico, lotes) | [`CD4BMCIK…ZZOF`](https://stellar.expert/explorer/testnet/contract/CD4BMCIKKOCVM66NYSC4LGWUWS4Z5ZMBU3KCVCSGZYI726ZVL7NZ2ZOF) · [contracts/deployments/testnet.json](contracts/deployments/testnet.json) |
| Lote de 1.024 receipts en 1 transacción | [`238f3737…`](https://stellar.expert/explorer/testnet/tx/238f3737b91b765835f0d8a535312c40c1a82a169e8de91f8f7198cdde0cc48d) |
| Contrato v1 (histórico) | [`CBG2DFZB…XJXZV`](https://stellar.expert/explorer/testnet/contract/CBG2DFZBHC3MEBN4UIVIVVNZX4YGI6TMRVRIK3TD4CVFKHMIKDXIJXZV); los receipts anclados ahí siguen verificando |
| Clave pública del attester | `ed25519:6848dcb2068c11bd1771b88e`, publicada en el mismo archivo |
| Compra honesta · pago / anclaje (v1) | [`715cdfed…`](https://stellar.expert/explorer/testnet/tx/715cdfed6d32b9c136e6ea619ec520b30786b1bdaea335ada62a7a3390afa17a) · [`ac682bc0…`](https://stellar.expert/explorer/testnet/tx/ac682bc03c942612dd43ebe58b4b3201a577163ac4c0d61f844c0b1832f8eddd) |
| Compra envenenada · pago / anclaje `TAINTED` (v1) | [`a8386b9c…`](https://stellar.expert/explorer/testnet/tx/a8386b9c6f49cc2d4d48b77b97f4e804c5fa844d679ea8e9720d7b61a7695af4) · [`c8f787c7…`](https://stellar.expert/explorer/testnet/tx/c8f787c78e16ba183299a060cbab212ee4ce5286a79ec338129bfab23c2d5397) |
| Vendedor que **no controlamos** | Stellar Bazaar x402 (`bazaar.browns.studio`), con `npm run demo:external` |

En la compra envenenada **el pago fue perfecto**: x402 hizo su trabajo. Lo que falló fue el
contenido, y eso ningún riel de pago lo mide.

## Probarlo

Requisitos: Node 20+ y npm. Para las demos en red, además, una cuenta de testnet con USDC y
el [Stellar CLI](https://developers.stellar.org/docs/tools/cli).

```bash
npm install
npm run typecheck
npm test                 # 202 tests TS, sin red
(cd contracts && cargo test)   # 47 tests de contratos
npm run benchmark        # corpus de ataques + métrica, sin red
```

Demos contra testnet:

```bash
npm run attester:init    # una vez: crea la clave del attester y publica su mitad pública

export AEGIS_BUYER_SECRET="$(stellar keys show aegis-buyer)"
export AEGIS_SELLER_ACCOUNT="$(stellar keys address aegis-seller)"

npm run demo:attack      # 4 pasos: compra honesta, vendedor hostil, corte de cascada, consulta on-chain
npm run demo:external -- "https://bazaar.browns.studio/api/x402/swap-risk?pair=XLM/USDC&amount=2500&side=buy"

npm run verify:receipt -- .aegis/receipts/<paymentHash>.json   # verificación como tercero, sin secretos
npm run verify:deployment  # contrato de punta a punta, incluido un lote de 1.024
```

`AEGIS_SKIP_ANCHOR=1` omite el anclaje on-chain (ensayos rápidos), y `AEGIS_SKIP_PURCHASE=1`
corre `demo:external` sin gastar nada.

Con `AEGIS_RECLAIM_APP_ID` y `AEGIS_RECLAIM_APP_SECRET` en `.env` (ver [.env.example](.env.example);
la app necesita zkFetch habilitado en el portal de Reclaim), `demo:external` pide la
respuesta pagada a través de un attestor y guarda la prueba de origen en el receipt.
`AEGIS_CONTENT_PROOF=0` lo desactiva.

**Sobre el vendedor externo.** El Bazaar es un servicio de otro desarrollador del ecosistema.
`demo:external` hace **una sola** compra de 0,001 USDC de testnet. Las pruebas de rechazo no
llegan a su servidor, porque el signer se niega antes de firmar. La prueba de manipulación
altera **nuestra copia local** de su respuesta: su servicio nunca devolvió nada malicioso.

## Métrica medida

Corpus de 20 ataques en 9 familias más 5 entregas legítimas, pasados por el mismo
`assessDelivery` que usa la demo (`npm run benchmark`):

| | Resultado |
|---|---|
| Bloqueados, familias cubiertas | **15 / 15** · cota inferior 95 % (Clopper-Pearson) **81,9 %** |
| Bloqueados, corpus completo | 15 / 20 · cota inferior 95 % 54,4 % |
| Falsos positivos sobre entregas legítimas | **0 / 5** |
| Residuales declarados (llegan al contexto) | 5: payload en base64 y hex, homoglifo cirílico, ataque en varios turnos (2) |

Los residuales se publican a propósito: son los límites conocidos del detector, no fallos
ocultos. Y el corpus es chico; la cota inferior importa más que el 100 %.

## Qué prueba y qué no

**Sí:** el agente firmó un commitment antes de pagar; el pago x402 liquidó en testnet; el
contenido se hasheó localmente; el receipt liga commitment, pago, vendedor, contenido y
veredicto; el contenido envenenado quedó en cuarentena; el gasto siguiente fue denegado; el
veredicto quedó anclado en Soroban y cualquiera puede verificarlo.

**No:**
- En modo clásico (cuenta `G…`), el contrato **no** verifica que el pago haya liquidado: ancla
  una *atestación del comprador*. Con la smart account, el pago y su conteo sí los verifica
  la cadena (garantías C y A+B), y con Reclaim el origen del contenido (D).
- Ninguna capa verifica que el contenido sea **verdadero**: D prueba que el vendedor lo envió,
  no que sea correcto.
- `seller_score` **no** es reputación objetiva. Es un agregado de atestaciones, y se puede
  inflar o atacar (colusión, griefing). Los OK de lotes se cuentan aparte (`batched_ok`):
  el contrato no ve las hojas, así que ese conteo es la palabra del comprador, con un tope de
  1.024 por lote.
- En los **lotes** (modo clásico) el contrato no impide que un mismo pago aparezca en dos: nunca
  ve las hojas. Los **rangos** de la smart account sí lo impiden.
- La firma del receipt es del comprador, **no** prueba que el vendedor haya incumplido.
- Datos plausibles pero sutilmente falsos (un precio manipulado) **no** son detectables por
  esta capa; eso requiere oráculos o arbitraje.
- No elimina la inyección de instrucciones: la detecta con patrones conocidos y declara sus
  residuales.

## Límites conocidos

- **La clave de commitments vive en el proceso del lanzador**, que en la demo es el mismo del
  agente. El signer ya no acepta claves traídas por la petición (se fijan al arrancarlo),
  pero un atacante con control total de ese proceso podría usarla. El paso siguiente es el
  de la próxima sección.
- **Testnet.** El facilitator de x402.org es solo de testnet; en mainnet el nombrado por la
  documentación de Stellar es OpenZeppelin Channels.
- **Vendedores que no cooperan.** Todas las compras de la demo son de nivel T2 (solo existe
  el commitment del comprador). El nivel T1, donde el vendedor firma una oferta antes del
  pago y permite atribuirle la culpa, está diseñado pero fuera de alcance.

## Hacia dónde va, en Stellar

- **Smart accounts con política on-chain.** La guía oficial *Advanced contract account
  patterns* describe los *policy signers* y los *external policy contracts*
  (`approve(auth_context)`). Mover el guard de AegisOS a la política de la smart account del
  comprador hace que el control lo aplique la cuenta en Stellar, no un proceso nuestro.
- **MPP (Machine Payments Protocol).** Su modo *Session* está hecho para agentes de alta
  frecuencia, que es exactamente nuestra tesis. El `paymentHash` ya incluye el esquema de
  pago; MPP es el siguiente adaptador.
- **Integridad de catálogo.** Un listado forjado en un Bazaar es contenido no verificado
  *antes* del pago; es el mismo binding aplicado al descubrimiento.

## Trabajos relacionados

Proyectos del ecosistema que miran partes del problema: *AgentOracle* (verificación de
afirmaciones vendida vía x402), *Sentryx402* (presupuestos y seguimiento de recibos) y
*Warden ZK Receipts* (recibos de a qué accedió un agente). Ninguno liga
commitment–pago–contenido ni bloquea el gasto posterior. REAPP (SCF #43) cubre la
autorización; AegisOS es complementario.

## Estructura

```
packages/core          codificación canónica, criptografía, intents, ledger, política
packages/proof         commitments, receipts, veredicto de entrega, admisión, árbol Merkle
packages/plugin-eliza  gateway de memoria, detección de riesgo (en/es), drafts
packages/x402          signer aislado + guard, cliente x402, cliente del contrato, lotes
packages/signer        signer de operaciones tipadas + simulador
contracts/aegis-proof  contrato Soroban de anclaje individual y por lotes (21 tests, 9,5 KB de wasm)
apps/demo-x402         demo:attack, demo:external, verify:receipt, attester:init
apps/benchmark         corpus de ataques y métrica
```

Los paquetes `core`, `proof`, `signer` y `plugin-eliza` no tienen dependencias externas de
runtime: solo módulos `node:*` y `@aegisos/core`.

Modelo de seguridad completo: [docs/security-model.md](docs/security-model.md).
