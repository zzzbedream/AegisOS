import type {
  EnforcedHostConfiguration,
  HostComponentDescriptor,
  PreflightReport,
  PreflightViolation,
} from "./types.js";

const DEFAULT_GATEWAY_ID = "aegis-memory-gateway";

/**
 * Strings matching these patterns describe a path that can bypass Aegis.
 * Matching is deliberately conservative: in enforced mode a false positive is
 * safer than leaving a wallet, RPC, raw transaction, or raw memory path alive.
 */
const FORBIDDEN_ROUTE_PATTERNS: readonly RegExp[] = [
  /(?:^|[-_./:])wallet(?:$|[-_./:])|walletadapter|walletservice/i,
  /(?:^|[-_./:])(?:sign|signing|signer|privatekey|seed|mnemonic)(?:$|[-_./:])|rawsignature/i,
  /(?:^|[-_./:])(?:sendtransaction|broadcasttransaction|submittransaction|executetransaction|transfer)(?:$|[-_./:])|sendtx|broadcasttx/i,
  /(?:^|[-_./:])(?:rawxdr|xdr|calldata|rawtransaction)(?:$|[-_./:])/i,
  /(?:^|[-_./:])(?:rpc|jsonrpc)(?:$|[-_./:])|rpcclient|rpcprovider/i,
  /(?:^|[-_./:])(?:memory|messages?)[-_./:]?(?:read|write|store|persist|adapter|manager|database)?(?:$|[-_./:])/i,
  /(?:^|[-_./:])(?:swap|liquidity|bridge|borrow|repay|loan|approval|approve)(?:$|[-_./:])/i,
];

const INTERNAL_AEGIS_CAPABILITIES = new Set([
  "aegis-memory-gateway",
  "aegis-context-provider",
  "aegis-create-intent-draft",
]);

export class EnforcementConfigurationError extends Error {
  public readonly violations: readonly PreflightViolation[];

  public constructor(violations: readonly PreflightViolation[]) {
    super(`Aegis enforced bootstrap rejected ${violations.length} unsafe host route(s).`);
    this.name = "EnforcementConfigurationError";
    this.violations = violations;
  }
}

function valuesFor(component: HostComponentDescriptor): readonly string[] {
  return [component.id, ...(component.capabilities ?? []), ...(component.routes ?? [])];
}

function isForbidden(value: string): boolean {
  return FORBIDDEN_ROUTE_PATTERNS.some((pattern) => pattern.test(value));
}

function isKnownInternalCapability(value: string): boolean {
  return INTERNAL_AEGIS_CAPABILITIES.has(value.trim().toLowerCase());
}

function collectComponentViolations(component: HostComponentDescriptor, gatewayId: string): PreflightViolation[] {
  const violations: PreflightViolation[] = [];
  const isGateway = component.id === gatewayId;

  if (isGateway) {
    if (component.kind !== "service" || component.trustedAegisComponent !== true) {
      violations.push({
        componentId: component.id,
        reason: "The configured memory gateway must be an Aegis-trusted service.",
      });
    }
    if (!(component.capabilities ?? []).some((capability) => capability === "aegis-memory-gateway")) {
      violations.push({
        componentId: component.id,
        reason: "The configured memory gateway must explicitly expose aegis-memory-gateway.",
      });
    }
  }

  for (const value of valuesFor(component)) {
    if (isGateway && value === component.id) {
      continue;
    }
    if (isKnownInternalCapability(value)) {
      if (!component.trustedAegisComponent) {
        violations.push({
          componentId: component.id,
          reason: "Only Aegis-owned components may claim an internal Aegis capability.",
          matchedValue: value,
        });
      }
      continue;
    }

    if (isForbidden(value)) {
      violations.push({
        componentId: component.id,
        reason: "Direct wallet, transaction, RPC, or memory access can bypass Aegis enforced mode.",
        matchedValue: value,
      });
    }
  }

  return violations;
}

/**
 * Performs the static startup gate. It intentionally examines descriptors,
 * rather than trusting a host plugin's self-declared name or description.
 */
export function inspectEnforcedHost(configuration: EnforcedHostConfiguration): readonly PreflightViolation[] {
  const violations: PreflightViolation[] = [];
  const expectedGatewayId = configuration.requiredGatewayId ?? DEFAULT_GATEWAY_ID;

  if (configuration.mode !== "enforced") {
    violations.push({
      componentId: "host",
      reason: "Aegis can only start with mode=enforced.",
    });
  }

  if (configuration.memoryGatewayId !== expectedGatewayId) {
    violations.push({
      componentId: "host",
      reason: `memoryGatewayId must be ${expectedGatewayId} in enforced mode.`,
      matchedValue: configuration.memoryGatewayId,
    });
  }

  const gatewayMatches = configuration.components.filter((component) => component.id === configuration.memoryGatewayId);
  if (gatewayMatches.length !== 1) {
    violations.push({
      componentId: "host",
      reason: "Exactly one configured Aegis memory gateway is required.",
    });
  }

  const seenComponentIds = new Set<string>();
  for (const component of configuration.components) {
    if (seenComponentIds.has(component.id)) {
      violations.push({
        componentId: component.id,
        reason: "Duplicate component ids make enforcement ambiguous.",
      });
      continue;
    }
    seenComponentIds.add(component.id);
    violations.push(...collectComponentViolations(component, configuration.memoryGatewayId));
  }

  return violations;
}

/** Throws before a host runtime is initialized when an unsafe route is present. */
export function assertEnforcedHost(configuration: EnforcedHostConfiguration): PreflightReport {
  const violations = inspectEnforcedHost(configuration);
  if (violations.length > 0) {
    throw new EnforcementConfigurationError(violations);
  }

  return {
    mode: "enforced",
    accepted: true,
    gatewayId: configuration.memoryGatewayId,
    checkedComponents: configuration.components.length,
  };
}

/**
 * An explicit bootstrap object prevents a caller from silently skipping the
 * startup gate. Hosts should call start() before registering any agent loop.
 */
export class EnforcedBootstrap {
  private started = false;

  public constructor(private readonly configuration: EnforcedHostConfiguration) {}

  public start(): PreflightReport {
    if (this.started) {
      return {
        mode: "enforced",
        accepted: true,
        gatewayId: this.configuration.memoryGatewayId,
        checkedComponents: this.configuration.components.length,
      };
    }
    const report = assertEnforcedHost(this.configuration);
    this.started = true;
    return report;
  }

  public get isStarted(): boolean {
    return this.started;
  }
}
