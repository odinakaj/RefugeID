import { describe, it, expect, beforeEach } from "vitest";

interface AccessRequest {
  requester: string;
  owner: string;
  fields: string[];
  proof: Uint8Array;
  timestamp: bigint;
  granted: boolean;
}

interface MockContract {
  admin: string;
  paused: boolean;
  totalRequests: bigint;
  accessRequests: Map<bigint, AccessRequest>;
  permissions: Map<string, Map<string, string[]>>;
  REQUEST_TTL: bigint;
  MAX_ACTIVE_REQUESTS: bigint;
  blockHeight: bigint;

  isAdmin(caller: string): boolean;
  setPaused(caller: string, pause: boolean): { value: boolean } | { error: number };
  requestAccess(caller: string, owner: string, fields: string[], proof: Uint8Array): { value: bigint } | { error: number };
  grantAccess(caller: string, requestId: bigint): { value: boolean } | { error: number };
  revokeAccess(caller: string, requester: string): { value: boolean } | { error: number };
}

const mockContract: MockContract = {
  admin: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
  paused: false,
  totalRequests: 0n,
  accessRequests: new Map(),
  permissions: new Map(),
  REQUEST_TTL: 144n,
  MAX_ACTIVE_REQUESTS: 100n,
  blockHeight: 100n,

  isAdmin(caller: string) {
    return caller === this.admin;
  },

  setPaused(caller: string, pause: boolean) {
    if (!this.isAdmin(caller)) return { error: 200 };
    this.paused = pause;
    return { value: pause };
  },

  requestAccess(caller: string, owner: string, fields: string[], proof: Uint8Array) {
    if (this.paused) return { error: 203 };
    if (fields.length === 0) return { error: 206 };
    if (this.totalRequests >= this.MAX_ACTIVE_REQUESTS) return { error: 207 };
    // Simulate validate-proof (assume always true for tests)
    const requestId = this.totalRequests + 1n;
    this.accessRequests.set(requestId, {
      requester: caller,
      owner: owner,
      fields,
      proof,
      timestamp: this.blockHeight,
      granted: false,
    });
    this.totalRequests = requestId;
    return { value: requestId };
  },

  grantAccess(caller: string, requestId: bigint) {
    if (this.paused) return { error: 203 };
    const request = this.accessRequests.get(requestId);
    if (!request) return { error: 201 };
    if (caller !== request.owner) return { error: 200 };
    if (this.blockHeight - request.timestamp >= this.REQUEST_TTL) return { error: 205 };
    if (request.granted) return { error: 206 };
    let ownerPerms = this.permissions.get(caller) || new Map();
    ownerPerms.set(request.requester, request.fields);
    this.permissions.set(caller, ownerPerms);
    this.accessRequests.set(requestId, { ...request, granted: true });
    return { value: true };
  },

  revokeAccess(caller: string, requester: string) {
    if (this.paused) return { error: 203 };
    const ownerPerms = this.permissions.get(caller);
    if (!ownerPerms) return { error: 201 };
    if (!ownerPerms.has(requester)) return { error: 201 };
    ownerPerms.delete(requester);
    this.permissions.set(caller, ownerPerms);
    return { value: true };
  },
};

describe("RefugeID Access Control Contract", () => {
  beforeEach(() => {
    mockContract.admin = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";
    mockContract.paused = false;
    mockContract.totalRequests = 0n;
    mockContract.accessRequests = new Map();
    mockContract.permissions = new Map();
    mockContract.blockHeight = 100n;
  });

  it("should request access successfully", () => {
    const fields = ["name", "age"];
    const proof = new Uint8Array([1, 2, 3]);
    const result = mockContract.requestAccess("ST3NB...", "ST2CY5...", fields, proof);
    expect(result).toEqual({ value: 1n });
    expect(mockContract.accessRequests.has(1n)).toBe(true);
    expect(mockContract.totalRequests).toBe(1n);
  });

  it("should prevent request if paused", () => {
    mockContract.setPaused(mockContract.admin, true);
    const fields = ["name"];
    const proof = new Uint8Array([1]);
    const result = mockContract.requestAccess("ST3NB...", "ST2CY5...", fields, proof);
    expect(result).toEqual({ error: 203 });
  });

  it("should grant access", () => {
    const fields = ["name", "age"];
    const proof = new Uint8Array([1, 2, 3]);
    mockContract.requestAccess("ST3NB...", "ST2CY5...", fields, proof);
    const result = mockContract.grantAccess("ST2CY5...", 1n);
    expect(result).toEqual({ value: true });
    expect(mockContract.accessRequests.get(1n)?.granted).toBe(true);
    expect(mockContract.permissions.get("ST2CY5...")?.get("ST3NB...")).toEqual(fields);
  });

  it("should revoke access", () => {
    const fields = ["name", "age"];
    const proof = new Uint8Array([1, 2, 3]);
    mockContract.requestAccess("ST3NB...", "ST2CY5...", fields, proof);
    mockContract.grantAccess("ST2CY5...", 1n);
    const result = mockContract.revokeAccess("ST2CY5...", "ST3NB...");
    expect(result).toEqual({ value: true });
    expect(mockContract.permissions.get("ST2CY5...")?.has("ST3NB...")).toBe(false);
  });

  it("should not grant expired request", () => {
    const fields = ["name"];
    const proof = new Uint8Array([1]);
    mockContract.requestAccess("ST3NB...", "ST2CY5...", fields, proof);
    mockContract.blockHeight += 200n; // Exceed TTL
    const result = mockContract.grantAccess("ST2CY5...", 1n);
    expect(result).toEqual({ error: 205 });
  });

  it("should prevent non-owner from granting", () => {
    const fields = ["name"];
    const proof = new Uint8Array([1]);
    mockContract.requestAccess("ST3NB...", "ST2CY5...", fields, proof);
    const result = mockContract.grantAccess("ST4JQ...", 1n);
    expect(result).toEqual({ error: 200 });
  });

  it("should prevent revoke if no permissions exist", () => {
    const result = mockContract.revokeAccess("ST2CY5...", "ST3NB...");
    expect(result).toEqual({ error: 201 });
  });
});