import type { MemoryRiskSignal, MemorySource } from "./types.js";

/**
 * Fold text into a form that resists the cheap evasions: full-width and
 * compatibility forms, zero-width joiners, case, and accents.
 *
 * Matching only. NEVER hash or store the normalized form: the evidence that
 * gets bound to a delivery receipt must be the bytes actually received, or the
 * content hash stops meaning anything.
 */
export function normalizeForMatching(value: string): string {
  return value
    .normalize("NFKC")
    .replace(/[​-‍⁠﻿]/g, "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Collapse away separators so letter-spaced payloads ("i g n o r a") reduce to
 * the word they were hiding. Patterns are written with `\s*` so a single
 * expression matches both the spaced and the collapsed form.
 */
function stripSeparators(normalized: string): string {
  return normalized.replace(/[\s._\-*|/\\]+/g, "");
}

/** Six or more single characters in a row is not prose; it is filter evasion. */
const LETTER_SPACING = /(?:(?:^|\s)[a-z0-9](?=\s)){6,}/;

const INJECTION_PATTERNS: readonly [RegExp, MemoryRiskSignal["kind"], number, string][] = [
  // --- English ---
  [
    /(?:ignore|disregard|override|forget)\s*(?:all\s*)?(?:previous|prior|system|safety)\s*(?:instructions|rules|messages)/,
    "PROMPT_INJECTION",
    85,
    "Instruction hierarchy override language",
  ],
  [
    /(?:system\s*prompt|developer\s*message|hidden\s*instruction|jailbreak)/,
    "PROMPT_INJECTION",
    70,
    "Attempt to reference privileged instruction channels",
  ],
  [
    /(?:send|transfer|withdraw|swap|approve|sign)\b[\s\S]{0,80}\b(?:without|no)\s*(?:approval|confirmation|review)/,
    "FINANCIAL_AUTHORITY_CLAIM",
    90,
    "Attempts to remove financial approval",
  ],
  [
    /(?:private\s*key|seed\s*phrase|mnemonic|api\s*key|wallet\s*secret)/,
    "SECRET_REQUEST",
    75,
    "Requests or embeds a credential-like secret",
  ],
  [
    /(?:you\s*(?:are|have\s*been)\s*(?:authorized|approved)|owner\s*(?:already\s*)?approved|policy\s*(?:already\s*)?allows)/,
    "FINANCIAL_AUTHORITY_CLAIM",
    65,
    "Unverified claim of authority",
  ],
  [
    /(?:run|call|use)\s*(?:this\s*)?(?:tool|command|transaction|rpc|calldata|xdr)\b/,
    "UNTRUSTED_INSTRUCTION",
    45,
    "External text contains tool or transaction instruction",
  ],

  // --- Spanish ---
  // The corpus and the demo are in Spanish. Without these, a chat- or
  // tool-sourced injection scores only its source base (25-35) and is never
  // quarantined.
  [
    /(?:ignora|ignore|omite|olvida|descarta)\s*(?:las\s*|los\s*|todas\s*las\s*|todos\s*los\s*)?(?:instrucciones|reglas|indicaciones|ordenes|mensajes)\s*(?:anteriores|previas|previos|del\s*sistema)?/,
    "PROMPT_INJECTION",
    85,
    "Anulacion de jerarquia de instrucciones (es)",
  ],
  [
    /(?:nota|mensaje|aviso|instruccion)\s*(?:del|de)\s*sistema/,
    "PROMPT_INJECTION",
    70,
    "Suplantacion de canal de sistema (es)",
  ],
  [
    /(?:actua|comportate|responde)\s*como\s*(?:system|developer|administrador|desarrollador)/,
    "PROMPT_INJECTION",
    70,
    "Suplantacion de rol privilegiado (es)",
  ],
  [
    /(?:transfiere|envia|paga|retira|aprueba|firma)\b[\s\S]{0,80}\b(?:sin)\s*(?:aprobacion|confirmacion|revision|autorizacion)/,
    "FINANCIAL_AUTHORITY_CLAIM",
    90,
    "Intenta eliminar la aprobacion financiera (es)",
  ],
  [
    /(?:la\s*)?(?:direccion|cuenta|billetera|wallet)\s*(?:del\s*)?(?:tesoro|tesoreria|deposito)\s*(?:ha\s*)?(?:cambio|cambiado|es\s*ahora)/,
    "FINANCIAL_AUTHORITY_CLAIM",
    90,
    "Sustitucion de destinatario de fondos (es)",
  ],
  [
    /(?:revela|muestra|entrega|comparte)\s*(?:la\s*|el\s*|tu\s*)?(?:clave\s*privada|semilla|frase\s*semilla|mnemonica|secreto)/,
    "SECRET_REQUEST",
    75,
    "Solicita material de clave (es)",
  ],
  [
    /(?:ya\s*)?(?:estas|fuiste|has\s*sido)\s*(?:autorizado|aprobado)|(?:el\s*)?(?:dueno|propietario)\s*(?:ya\s*)?(?:aprobo|autorizo)|(?:la\s*)?politica\s*(?:ya\s*)?(?:lo\s*)?permite/,
    "FINANCIAL_AUTHORITY_CLAIM",
    65,
    "Afirmacion de autoridad no verificada (es)",
  ],
  [
    /(?:desactiva|deshabilita|elimina|omite)\s*(?:las\s*|los\s*)?(?:restricciones|politicas|limites|controles|validaciones)/,
    "PROMPT_INJECTION",
    85,
    "Intenta desactivar controles (es)",
  ],
];

const SOURCE_BASE_TAINT: Readonly<Record<MemorySource, number>> = {
  chat: 25,
  document: 30,
  tool: 35,
  external_memory: 45,
  system: 5,
};

export function assessMemoryRisk(content: string, source: MemorySource): {
  readonly taintScore: number;
  readonly signals: readonly MemoryRiskSignal[];
} {
  const normalized = normalizeForMatching(content);
  const collapsed = stripSeparators(normalized);

  const signals: MemoryRiskSignal[] = [];

  if (LETTER_SPACING.test(normalized)) {
    signals.push({
      kind: "PROMPT_INJECTION",
      score: 60,
      evidence: "Letter-spaced text consistent with filter evasion",
    });
  }

  for (const [pattern, kind, score, evidence] of INJECTION_PATTERNS) {
    // The collapsed pass is what catches "i g n o r a l a s ..."; patterns use
    // `\s*` rather than `\s+` so one expression covers both forms.
    if (pattern.test(normalized) || pattern.test(collapsed)) {
      signals.push({ kind, score, evidence });
    }
  }

  const highestSignal = signals.reduce((highest, signal) => Math.max(highest, signal.score), 0);
  const combined = Math.min(100, Math.max(SOURCE_BASE_TAINT[source], highestSignal));
  return { taintScore: combined, signals };
}
