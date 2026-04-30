import { describe, it, expect } from "vitest";
import { encryptData, decryptData } from "../../src/utils/crypto";

describe("crypto", () => {
  describe("encryptData", () => {
    it("should produce a base64 string", async () => {
      const result = await encryptData({ test: "data" }, "password");
      expect(result).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });

    it("should produce different output for each call (random salt/IV)", async () => {
      const encrypted1 = await encryptData({ value: 42 }, "same-password");
      const encrypted2 = await encryptData({ value: 42 }, "same-password");
      expect(encrypted1).not.toBe(encrypted2);
    });

    it("should produce different output for different passwords", async () => {
      const data = { secret: true };
      const encrypted1 = await encryptData(data, "password1");
      const encrypted2 = await encryptData(data, "password2");
      expect(encrypted1).not.toBe(encrypted2);
    });

    it("should handle empty string password", async () => {
      const result = await encryptData({ test: true }, "");
      expect(result).toMatch(/^[A-Za-z0-9+/]+=*$/);
      expect(result.length).toBeGreaterThan(0);
    });

    it("should handle complex nested objects", async () => {
      const data = {
        accounts: [
          { email: "a@b.com", id: 1, nested: { flag: true } },
          { email: "c@d.com", id: 2, nested: { flag: false } },
        ],
        metadata: { version: "1.0", count: 2 },
      };
      const result = await encryptData(data, "test");
      expect(result).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });

    it("should produce output with minimum size (salt + IV + at least some ciphertext)", async () => {
      // salt(16) + iv(12) = 28 bytes → base64 of 28 bytes ≈ 38 chars minimum
      const result = await encryptData({}, "password");
      expect(result.length).toBeGreaterThan(30);
    });
  });

  describe("decryptData", () => {
    it("should decrypt data encrypted with the same password", async () => {
      const original = { key: "value", number: 42, flag: true };
      const encrypted = await encryptData(original, "my-password");
      const decrypted = await decryptData(encrypted, "my-password");
      expect(decrypted).toEqual(original);
    });

    it("should handle arrays", async () => {
      const original = [{ id: 1 }, { id: 2 }, { id: 3 }];
      const encrypted = await encryptData(original, "pass");
      const decrypted = await decryptData(encrypted, "pass");
      expect(decrypted).toEqual(original);
    });

    it("should handle empty object", async () => {
      const original = {};
      const encrypted = await encryptData(original, "password");
      const decrypted = await decryptData(encrypted, "password");
      expect(decrypted).toEqual({});
    });

    it("should throw with wrong password", async () => {
      const encrypted = await encryptData({ secret: true }, "correct");
      await expect(decryptData(encrypted, "wrong")).rejects.toThrow(
        "Decryption failed. Incorrect password or corrupted data.",
      );
    });

    it("should throw with empty string when encrypted with non-empty password", async () => {
      const encrypted = await encryptData({ secret: true }, "nonempty");
      await expect(decryptData(encrypted, "")).rejects.toThrow();
    });

    it("should throw with non-empty password when encrypted with empty string", async () => {
      const encrypted = await encryptData({ secret: true }, "");
      await expect(decryptData(encrypted, "wrong")).rejects.toThrow();
    });

    it("should throw with corrupted data", async () => {
      await expect(
        decryptData("not-valid-base64!!!", "password"),
      ).rejects.toThrow();
    });

    it("should throw with truncated base64", async () => {
      // Valid base64 but too short to contain salt + IV + ciphertext
      await expect(decryptData("dGVzdA==", "password")).rejects.toThrow();
    });

    it("should handle empty string password roundtrip", async () => {
      const original = { data: "test" };
      const encrypted = await encryptData(original, "");
      const decrypted = await decryptData(encrypted, "");
      expect(decrypted).toEqual(original);
    });
  });

  describe("roundtrip", () => {
    it("should preserve string values with special characters", async () => {
      const original = { text: "Hello 世界! 🌍" };
      const encrypted = await encryptData(original, "pass");
      const decrypted = await decryptData(encrypted, "pass");
      expect(decrypted).toEqual(original);
    });

    it("should preserve null values", async () => {
      const original = { a: 1, b: null, c: undefined };
      // Note: JSON.stringify drops undefined keys, so we test what actually serializes
      const encrypted = await encryptData({ a: 1, b: null }, "pass");
      const decrypted = await decryptData(encrypted, "pass");
      expect(decrypted).toEqual({ a: 1, b: null });
    });

    it("should handle large data", async () => {
      const original = Array.from({ length: 100 }, (_, i) => ({
        index: i,
        payload: "x".repeat(100),
      }));
      const encrypted = await encryptData(original, "password");
      const decrypted = await decryptData(encrypted, "password");
      expect(decrypted).toEqual(original);
    });
  });
});
