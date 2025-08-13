import { describe, it, expect, beforeEach } from "vitest";

interface Identity {
  "encrypted-data": Uint8Array;
  "creation-height": bigint;
  "expiry-height": bigint;
}

interface MockContract {
  admin: string;
  paused: boolean;
  totalIdentities: bigint;
  identities: Map<string, Identity>;
  approvedIssuers: Map<string, boolean>;
  EXPIRY_BLOCKS: bigint;
  blockHeight: bigint;

  isAdmin(caller: string): boolean;
  setPaused(caller: string, pause: boolean): { value: boolean } | { error: number };
  addIssuer(caller: string, issuer: string): { value: boolean } | { error: number };
  removeIssuer(caller: string, issuer: string): { value: boolean } | { error: number };
  createIdentity(caller: string, encryptedData: Uint8Array, customExpiry: bigint): { value: string } | { error: number };
  updateIdentity(caller: string, newEncryptedData: Uint8Array): { value: boolean } | { error: number };
  extendExpiry(caller: string, additionalBlocks: bigint): { value: boolean } | { error: number };
  deleteIdentity(caller: string): { value: boolean } | { error: number };
}

const mockContract: MockContract = {
  admin: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
  paused: false,
  totalIdentities: 0n,
  identities: new Map(),
  approvedIssuers: new Map(),
  EXPIRY_BLOCKS: 52560n,
  blockHeight: 100n,

  isAdmin(caller: string) {
    return caller === this.admin;
  },

  setPaused(caller: string, pause: boolean) {
    if (!this.isAdmin(caller)) return { error: 100 };
    this.paused = pause;
    return { value: pause };
  },

  addIssuer(caller: string, issuer: string) {
    if (!this.isAdmin(caller)) return { error: 100 };
    this.approvedIssuers.set(issuer, true);
    return { value: true };
  },

  removeIssuer(caller: string, issuer: string) {
    if (!this.isAdmin(caller)) return { error: 100 };
    this.approvedIssuers.delete(issuer);
    return { value: true };
  },

  createIdentity(caller: string, encryptedData: Uint8Array, customExpiry: bigint) {
    if (this.paused) return { error: 104 };
    if (encryptedData.length === 0) return { error: 101 };
    if (this.identities.has(caller)) return { error: 102 };
    if (customExpiry <= 0n || customExpiry > this.EXPIRY_BLOCKS) return { error: 108 };
    const expiry = this.blockHeight + customExpiry;
    this.identities.set(caller, {
      "encrypted-data": encryptedData,
      "creation-height": this.blockHeight,
      "expiry-height": expiry,
    });
    this.totalIdentities += 1n;
    return { value: caller };
  },

  updateIdentity(caller: string, newEncryptedData: Uint8Array) {
    if (this.paused) return { error: 104 };
    if (newEncryptedData.length === 0) return { error: 101 };
    const identity = this.identities.get(caller);
    if (!identity) return { error: 103 };
    if (this.blockHeight >= identity["expiry-height"]) return { error: 107 };
    this.identities.set(caller, { ...identity, "encrypted-data": newEncryptedData });
    return { value: true };
  },

  extendExpiry(caller: string, additionalBlocks: bigint) {
    if (this.paused) return { error: 104 };
    if (additionalBlocks <= 0n) return { error: 106 };
    const identity = this.identities.get(caller);
    if (!identity) return { error: 103 };
    if (this.blockHeight >= identity["expiry-height"]) return { error: 107 };
    const newExpiry = identity["expiry-height"] + additionalBlocks;
    if (newExpiry - identity["creation-height"] > this.EXPIRY_BLOCKS) return { error: 108 };
    this.identities.set(caller, { ...identity, "expiry-height": newExpiry });
    return { value: true };
  },

  deleteIdentity(caller: string) {
    if (this.paused) return { error: 104 };
    if (!this.identities.has(caller)) return { error: 103 };
    this.identities.delete(caller);
    this.totalIdentities -= 1n;
    return { value: true };
  },
};

describe("RefugeID Identity Creation Contract", () => {
  beforeEach(() => {
    mockContract.admin = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";
    mockContract.paused = false;
    mockContract.totalIdentities = 0n;
    mockContract.identities = new Map();
    mockContract.approvedIssuers = new Map();
    mockContract.blockHeight = 100n;
  });

  it("should create identity successfully", () => {
    const data = new Uint8Array([1, 2, 3]);
    const result = mockContract.createIdentity("ST2CY5...", data, 1000n);
    expect(result).toEqual({ value: "ST2CY5..." });
    expect(mockContract.identities.has("ST2CY5...")).toBe(true);
    expect(mockContract.totalIdentities).toBe(1n);
  });

  it("should prevent creation if paused", () => {
    mockContract.setPaused(mockContract.admin, true);
    const data = new Uint8Array([1, 2, 3]);
    const result = mockContract.createIdentity("ST2CY5...", data, 1000n);
    expect(result).toEqual({ error: 104 });
  });

  it("should update identity", () => {
    const data = new Uint8Array([1, 2, 3]);
    mockContract.createIdentity("ST2CY5...", data, 1000n);
    const newData = new Uint8Array([4, 5, 6]);
    const result = mockContract.updateIdentity("ST2CY5...", newData);
    expect(result).toEqual({ value: true });
    expect(mockContract.identities.get("ST2CY5...")?.["encrypted-data"]).toEqual(newData);
  });

  it("should extend expiry", () => {
    const data = new Uint8Array([1, 2, 3]);
    mockContract.createIdentity("ST2CY5...", data, 1000n);
    const result = mockContract.extendExpiry("ST2CY5...", 500n);
    expect(result).toEqual({ value: true });
    expect(mockContract.identities.get("ST2CY5...")?.["expiry-height"]).toBe(100n + 1000n + 500n);
  });

  it("should delete identity", () => {
    const data = new Uint8Array([1, 2, 3]);
    mockContract.createIdentity("ST2CY5...", data, 1000n);
    const result = mockContract.deleteIdentity("ST2CY5...");
    expect(result).toEqual({ value: true });
    expect(mockContract.identities.has("ST2CY5...")).toBe(false);
    expect(mockContract.totalIdentities).toBe(0n);
  });

  it("should add and remove issuer as admin", () => {
    const resultAdd = mockContract.addIssuer(mockContract.admin, "ST3NB...");
    expect(resultAdd).toEqual({ value: true });
    expect(mockContract.approvedIssuers.get("ST3NB...")).toBe(true);

    const resultRemove = mockContract.removeIssuer(mockContract.admin, "ST3NB...");
    expect(resultRemove).toEqual({ value: true });
    expect(mockContract.approvedIssuers.has("ST3NB...")).toBe(false);
  });

  it("should prevent non-admin from adding issuer", () => {
    const result = mockContract.addIssuer("ST2CY5...", "ST3NB...");
    expect(result).toEqual({ error: 100 });
  });
});