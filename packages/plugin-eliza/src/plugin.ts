import type { AgentRuntimeLike } from "./framework.js";
import { AegisContextProvider } from "./context-provider.js";
import { AegisDraftStore, CreateIntentDraftAction } from "./draft-action.js";
import { AegisMemoryGateway } from "./memory-gateway.js";
import { AegisPolicyService } from "./policy-service.js";
import { EnforcedBootstrap } from "./preflight.js";
import type { AegisPluginOptions } from "./types.js";

/**
 * Narrow plugin contract intentionally excludes generic wallet, RPC, signer,
 * and raw-memory services. A host can adapt this structural shape to ElizaOS
 * without importing ElizaOS into Aegis's trusted computing base.
 */
export interface AegisElizaPlugin {
  readonly name: "@aegisos/plugin-eliza";
  readonly description: string;
  readonly actions: readonly [CreateIntentDraftAction];
  readonly providers: readonly [AegisContextProvider];
  readonly services: readonly [AegisMemoryGateway, AegisPolicyService];
  readonly bootstrap: EnforcedBootstrap;
  readonly gateway: AegisMemoryGateway;
  readonly drafts: AegisDraftStore;
  readonly policy: AegisPolicyService;
  readonly init: (runtime: AgentRuntimeLike) => Promise<void>;
}

export function createAegisPlugin(options: AegisPluginOptions): AegisElizaPlugin {
  const bootstrap = new EnforcedBootstrap(options.host);
  const gateway = new AegisMemoryGateway(options);
  const drafts = new AegisDraftStore(gateway, {
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.draftIdFactory === undefined ? {} : { idFactory: options.draftIdFactory }),
  });
  const provider = new AegisContextProvider(gateway);
  const policy = new AegisPolicyService(gateway, options.now);
  const action = new CreateIntentDraftAction(drafts);
  const actions = Object.freeze([action] as const);
  const providers = Object.freeze([provider] as const);
  const services = Object.freeze([gateway, policy] as const);

  return Object.freeze({
    name: "@aegisos/plugin-eliza",
    description: "Enforced Aegis memory boundary and typed draft-only financial action for ElizaOS-shaped hosts.",
    actions,
    providers,
    services,
    bootstrap,
    gateway,
    drafts,
    policy,
    async init(_runtime: AgentRuntimeLike): Promise<void> {
      bootstrap.start();
    },
  });
}
