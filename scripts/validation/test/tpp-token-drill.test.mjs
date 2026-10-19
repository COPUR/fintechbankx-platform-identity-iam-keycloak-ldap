import test from "node:test";
import assert from "node:assert/strict";
import { decodeJwt, tppTokenErrors } from "../../realm/tpp-token-drill.mjs";

// Claims of a real access token for an onboarded TPP (local drill against
// Keycloak 26.7.5, REALM_AS_CODE.md "TPP token drill"), trimmed.
const claims = { azp: "of-tpp-drill-pay", fbx_client_type: "open-finance-tpp", scope: "openid payments", aud: ["svc-pay-request-to-pay"], cnf: { jkt: "thumb" } };

test("drill assertion: client type, azp and payments scope as the payment services check them", () => {
  assert.deepEqual(tppTokenErrors(claims, { clientId: "of-tpp-drill-pay", expectPayments: true, dpopJkt: "thumb" }), []);
  assert.deepEqual(tppTokenErrors({ ...claims, scope: "openid" }, { clientId: "of-tpp-drill-pay", expectPayments: false }), []);
  assert.deepEqual(tppTokenErrors({ ...claims, fbx_client_type: undefined }, { clientId: "of-tpp-drill-pay" }), ['fbx_client_type is undefined, expected "open-finance-tpp"']);
  assert.deepEqual(tppTokenErrors(claims, { clientId: "of-tpp-other" }), ['azp is "of-tpp-drill-pay", expected "of-tpp-other"']);
  assert.deepEqual(tppTokenErrors({ ...claims, scope: "openid" }, { clientId: "of-tpp-drill-pay", expectPayments: true }), ["scope lacks payments (TPP authorised and payments requested)"]);
  assert.deepEqual(tppTokenErrors(claims, { clientId: "of-tpp-drill-pay", expectPayments: false }), ["scope carries payments, but the TPP is not authorised for payment services"]);
  assert.deepEqual(tppTokenErrors(claims, { clientId: "of-tpp-drill-pay", dpopJkt: "other" }), ['cnf.jkt is "thumb", expected the DPoP key thumbprint']);
});

test("drill decodes the access token payload", () => {
  const jwt = ["e30", Buffer.from(JSON.stringify(claims)).toString("base64url"), "sig"].join(".");
  assert.deepEqual(decodeJwt(jwt), claims);
});
