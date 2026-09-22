/**
 * Minimal, framework-shaped contracts used by this package.
 *
 * Aegis deliberately does not import ElizaOS at build time: these structural
 * interfaces make the plugin usable by ElizaOS adapters without giving a host
 * framework any authority over the security boundary.
 */

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export interface AgentRuntimeLike {
  readonly agentId: string;
  readonly characterName?: string;
}

export interface ElizaMessageLike {
  readonly id: string;
  readonly content: string;
  readonly userId?: string;
  readonly roomId?: string;
  readonly createdAt?: number;
  readonly metadata?: Readonly<Record<string, JsonValue>>;
}

export interface ElizaActionLike<Input, Output> {
  readonly name: string;
  readonly description: string;
  readonly similes: readonly string[];
  readonly validate: (runtime: AgentRuntimeLike, input: unknown) => input is Input;
  readonly handler: (runtime: AgentRuntimeLike, input: Input) => Promise<Output>;
}

export interface ElizaProviderLike<Context> {
  readonly name: string;
  readonly description: string;
  readonly get: (runtime: AgentRuntimeLike, message: ElizaMessageLike) => Promise<Context>;
}

export interface ElizaServiceLike {
  readonly serviceType: string;
  readonly capability: string;
}

export interface ElizaPluginLike {
  readonly name: string;
  readonly description: string;
  readonly actions: readonly ElizaActionLike<unknown, unknown>[];
  readonly providers: readonly ElizaProviderLike<unknown>[];
  readonly services: readonly ElizaServiceLike[];
  readonly init: (runtime: AgentRuntimeLike) => Promise<void>;
}
