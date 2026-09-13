import { afterEach, describe, expect, test } from "bun:test";
import { checkVerification } from "./verify";

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
});

describe("checkVerification", () => {
  test("parses a verified response", async () => {
    global.fetch = (async () =>
      new Response(
        JSON.stringify({
          is_verified: true,
          message: "On chain program verified",
          repo_url: "https://github.com/Ellipsis-Labs/phoenix-v1",
          commit: "None",
          is_frozen: false,
          is_closed: false,
        })
      )) as typeof fetch;

    const result = await checkVerification("PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY");
    expect(result.isVerified).toBe(true);
    expect(result.repoUrl).toBe("https://github.com/Ellipsis-Labs/phoenix-v1");
    expect(result.commit).toBeNull(); // "None" string normalized to null
  });

  test("treats a non-OK response as not verified rather than throwing", async () => {
    global.fetch = (async () => new Response("not found", { status: 404 })) as typeof fetch;

    const result = await checkVerification("SomeRandomUnverifiedProgram1111111111111111");
    expect(result.isVerified).toBe(false);
    expect(result.repoUrl).toBeNull();
  });
});
