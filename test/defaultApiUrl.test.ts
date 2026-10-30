import { describe, it, expect } from "vitest";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import { loadServerConfig } from "../src/config.js";
import { resolveAuth } from "../src/auth/resolve.js";
import { NetBirdOAuthProvider } from "../src/oauth/provider.js";
import { renderLoginPage } from "../src/oauth/loginPage.js";
import { pkcePair, silentLogger } from "./helpers.js";

describe("configured API URL fallback", () => {
  it.each([undefined, "", "   "])("uses the configured URL for direct PAT with header %j", async (url) => {
    const config = loadServerConfig({ NETBIRD_API_URL: "https://self.hosted/api///" });
    await expect(resolveAuth(
      { "x-netbird-token": "pat", "x-netbird-api-url": url },
      {
        ...config,
        ...config.http,
        directPatEnabled: true,
        verifyPat: async () => "ok",
      },
    )).resolves.toEqual({ token: "pat", baseUrl: "https://self.hosted/api" });
  });

  it.each([
    [undefined, "https://api.netbird.io"],
    ["https://override.example/", "https://override.example"],
  ])("preserves direct-PAT URL selection for header %j", async (url, expected) => {
    const config = loadServerConfig({
      NETBIRD_API_URL: url ? "https://self.hosted" : undefined,
      NETBIRD_ALLOWED_API_HOSTS: "override.example",
    });
    await expect(resolveAuth(
      { "x-netbird-token": "pat", "x-netbird-api-url": url },
      { ...config, ...config.http, directPatEnabled: true, verifyPat: async () => "ok" },
    )).resolves.toEqual({ token: "pat", baseUrl: expected });
  });

  it("rejects an explicit unallowlisted URL despite a configured fallback", async () => {
    const config = loadServerConfig({ NETBIRD_API_URL: "https://self.hosted" });
    await expect(resolveAuth(
      { "x-netbird-token": "pat", "x-netbird-api-url": "https://untrusted.example" },
      {
        ...config,
        ...config.http,
        directPatEnabled: true,
        verifyPat: async () => { throw new Error("must reject before verification"); },
      },
    )).rejects.toMatchObject({ code: "forbidden_host" });
  });

  it.each([undefined, "", "   "])("binds OAuth login to the configured URL for field %j", async (url) => {
    const config = loadServerConfig({ NETBIRD_API_URL: "https://self.hosted/api///" });
    const provider = new NetBirdOAuthProvider({
      ...config,
      logger: silentLogger,
      verifyPatOnLogin: false,
    });
    const client = {
      client_id: "client-123",
      redirect_uris: ["http://localhost:9999/cb"],
    } as OAuthClientInformationFull;
    await provider.clientsStore.registerClient!(client);
    const { verifier, challenge } = pkcePair();
    let location: string | undefined;
    const req = { body: {
      client_id: client.client_id,
      redirect_uri: client.redirect_uris[0],
      code_challenge: challenge,
      netbird_token: "pat",
      netbird_api_url: url,
    } } as unknown as import("express").Request;
    const res = {
      status() { return this; },
      setHeader() { return this; },
      send() {},
      redirect(_status: number, target: string) { location = target; },
    } as unknown as import("express").Response;
    await provider.handleLogin(req, res);
    expect(location).toBeDefined();
    const code = new URL(location!).searchParams.get("code")!;
    const tokens = await provider.exchangeAuthorizationCode(client, code, verifier, client.redirect_uris[0]);
    await expect(provider.resolveBinding(tokens.access_token)).resolves.toEqual({ token: "pat", baseUrl: "https://self.hosted/api" });
  });

  it("renders an empty API URL field so the configured fallback can apply", () => {
    const page = renderLoginPage({ clientId: "c", redirectUri: "", state: "", codeChallenge: "", scope: "", resource: "" });
    expect(page).toMatch(/name="netbird_api_url"[^>]*value=""/);
  });
});
