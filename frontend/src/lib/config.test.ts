import { describe, expect, it } from "vitest";
import { DEFAULT_API_ENDPOINT, loadConfig } from "./config";

describe("loadConfig", () => {
  it("applies defaults when unset and normalizes explicit values", () => {
    const defaults = loadConfig({});
    expect(defaults.apiEndpoint).toBe(DEFAULT_API_ENDPOINT);
    expect(defaults.expectedImageDigest).toBe("");

    const explicit = loadConfig({
      VITE_API_ENDPOINT: "https://api.example.com/",
      VITE_EXPECTED_IMAGE_DIGEST: " sha256:abc123 ",
    });
    expect(explicit.apiEndpoint).toBe("https://api.example.com");
    expect(explicit.expectedImageDigest).toBe("sha256:abc123");
  });
});
