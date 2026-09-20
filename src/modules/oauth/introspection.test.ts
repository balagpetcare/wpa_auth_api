import test from "node:test";
import assert from "node:assert/strict";
import {
  buildJwtIntrospectionResponse,
  isServiceTokenOwnedByClient,
} from "./introspection.js";

const issuer = "https://auth.example.test";

function payload(overrides: Record<string, unknown> = {}) {
  return {
    sub: "central-user-1",
    aud: "cpc-audience",
    iss: issuer,
    exp: Math.floor(Date.now() / 1000) + 900,
    iat: Math.floor(Date.now() / 1000),
    roles: ["central-admin"],
    ...overrides,
  };
}

test("introspection activates a token for the expected audience", () => {
  const result = buildJwtIntrospectionResponse(
    payload(),
    "cpc-audience",
    issuer,
    true,
  );
  assert.equal(result.active, true);
  if (result.active) {
    assert.equal(result.sub, "central-user-1");
    assert.equal(result.aud, "cpc-audience");
    assert.equal("scope" in result, false);
    assert.deepEqual(result.roles, ["central-admin"]);
  }
});

test("introspection rejects wrong and accepts multi-audience tokens", () => {
  assert.deepEqual(
    buildJwtIntrospectionResponse(
      payload({ aud: "other-application" }),
      "cpc-audience",
      issuer,
      true,
    ),
    { active: false },
  );
  const multi = buildJwtIntrospectionResponse(
    payload({ aud: ["other-application", "cpc-audience"] }),
    "cpc-audience",
    issuer,
    true,
  );
  assert.equal(multi.active, true);
});

test("introspection rejects wrong issuer, expired, and missing-sub payloads", () => {
  assert.deepEqual(
    buildJwtIntrospectionResponse(
      payload({ iss: "https://wrong.example.test" }),
      "cpc-audience",
      issuer,
      true,
    ),
    { active: false },
  );
  assert.deepEqual(
    buildJwtIntrospectionResponse(
      payload({ exp: 1 }),
      "cpc-audience",
      issuer,
      true,
    ),
    { active: false },
  );
  assert.deepEqual(
    buildJwtIntrospectionResponse(
      payload({ sub: "" }),
      "cpc-audience",
      issuer,
      true,
    ),
    { active: false },
  );
});

test("introspection rejects non-authenticatable accounts without disclosure", () => {
  assert.deepEqual(
    buildJwtIntrospectionResponse(payload(), "cpc-audience", issuer, false),
    { active: false },
  );
});

test("central roles are not represented as OAuth scopes", () => {
  const result = buildJwtIntrospectionResponse(
    payload({ roles: ["platform-admin"] }),
    "cpc-audience",
    issuer,
    true,
  );
  assert.equal(result.active, true);
  if (result.active) {
    assert.equal("scope" in result, false);
    assert.deepEqual(result.roles, ["platform-admin"]);
  }
});

test("service tokens are bound to their issuing client", () => {
  assert.equal(
    isServiceTokenOwnedByClient("client-a-db-id", "client-a-db-id"),
    true,
  );
  assert.equal(
    isServiceTokenOwnedByClient("client-a-db-id", "client-b-db-id"),
    false,
  );
});
