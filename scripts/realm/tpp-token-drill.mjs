#!/usr/bin/env node
// TPP token drill: obtains a real access token for an onboarded TPP client
// and checks the claims the request-to-pay service and the gateway rely on.
// Run against a non-production Keycloak with this realm imported and the TPP
// onboarded by scripts/realm/onboard-tpp.mjs (REALM_AS_CODE.md, "TPP token
// drill"). The repository has no Keycloak test harness in CI; this drill is
// the integration evidence and is run by hand.
//
// Flow (FAPI 2.0 + DPoP, as the realm policies require): PAR with
// private_key_jwt -> authorization endpoint -> PSU login form -> consent form
// -> authorization code -> token request with PKCE, private_key_jwt and a
// DPoP proof -> decode the access token.
//
// env: KEYCLOAK_URL, KEYCLOAK_REALM (default fintechbankx), TPP_CLIENT_ID,
//      TPP_PRIVATE_JWK_FILE (the TPP's private signing key, RSA, PS256; its
//      public half is the client's JWKS), TPP_KID, TPP_REDIRECT_URI,
//      DRILL_PSU_USERNAME, DRILL_PSU_PASSWORD (a test customer in /customers),
//      DRILL_SCOPE (default "openid payments"),
//      DRILL_EXPECT_PAYMENTS (true when the TPP is authorised for payments)
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const b64u = (b) => Buffer.from(b).toString("base64url");
export const decodeJwt = (jwt) => JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url").toString("utf8"));

// What the payment services check, as one function (unit-tested).
export function tppTokenErrors(claims, { clientId, expectPayments, dpopJkt }) {
  const errors = [];
  const scopes = String(claims.scope || "").split(" ").filter(Boolean);
  if (claims.fbx_client_type !== "open-finance-tpp") errors.push(`fbx_client_type is ${JSON.stringify(claims.fbx_client_type)}, expected "open-finance-tpp"`);
  if (claims.azp !== clientId) errors.push(`azp is ${JSON.stringify(claims.azp)}, expected ${JSON.stringify(clientId)}`);
  if (expectPayments === true && !scopes.includes("payments")) errors.push("scope lacks payments (TPP authorised and payments requested)");
  if (expectPayments === false && scopes.includes("payments")) errors.push("scope carries payments, but the TPP is not authorised for payment services");
  if (dpopJkt !== undefined && claims.cnf?.jkt !== dpopJkt) errors.push(`cnf.jkt is ${JSON.stringify(claims.cnf?.jkt)}, expected the DPoP key thumbprint`);
  return errors;
}

function sign(header, payload, key) {
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const opts = header.alg === "PS256"
    ? { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }
    : { key, dsaEncoding: "ieee-p1363" };
  return `${input}.${b64u(crypto.sign("sha256", Buffer.from(input), opts))}`;
}
const jwkThumbprint = (jwk) => b64u(crypto.createHash("sha256").update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest());

async function drill(env) {
  const issuer = `${env.KEYCLOAK_URL.replace(/\/+$/, "")}/realms/${env.KEYCLOAK_REALM || "fintechbankx"}`;
  const oidc = `${issuer}/protocol/openid-connect`;
  const clientId = env.TPP_CLIENT_ID;
  const clientKey = crypto.createPrivateKey({ key: JSON.parse(fs.readFileSync(env.TPP_PRIVATE_JWK_FILE, "utf8")), format: "jwk" });
  const assertion = () => sign({ alg: "PS256", kid: env.TPP_KID, typ: "JWT" }, { iss: clientId, sub: clientId, aud: issuer, jti: crypto.randomUUID(), iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60 }, clientKey);
  const clientAuth = () => ({ client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion() });
  const dpop = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const dpopJwk = dpop.publicKey.export({ format: "jwk" });
  const proof = (htm, htu) => sign({ typ: "dpop+jwt", alg: "ES256", jwk: dpopJwk }, { jti: crypto.randomUUID(), htm, htu, iat: Math.floor(Date.now() / 1000) }, dpop.privateKey);

  const jar = new Map();
  const browse = async (url, init = {}) => {
    const headers = { ...(init.headers || {}), cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") };
    const res = await fetch(url, { ...init, headers, redirect: "manual" });
    for (const c of res.headers.getSetCookie()) { const [kv] = c.split(";"); const i = kv.indexOf("="); jar.set(kv.slice(0, i), kv.slice(i + 1)); }
    return res;
  };
  const formAction = (html) => (html.match(/<form[^>]*action="([^"]+)"/) || [])[1]?.replace(/&amp;/g, "&");
  const hidden = (html) => Object.fromEntries([...html.matchAll(/<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"/g)].map((m) => [m[1], m[2]]));

  const verifier = b64u(crypto.randomBytes(32));
  const state = b64u(crypto.randomBytes(16));
  const par = await fetch(`${oidc}/ext/par/request`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ...clientAuth(), response_type: "code", redirect_uri: env.TPP_REDIRECT_URI, scope: env.DRILL_SCOPE || "openid payments", state, nonce: b64u(crypto.randomBytes(16)), code_challenge: b64u(crypto.createHash("sha256").update(verifier).digest()), code_challenge_method: "S256", dpop_jkt: jwkThumbprint(dpopJwk) })
  });
  const parBody = await par.json();
  if (!par.ok && parBody.error === "invalid_request" && /^Invalid scopes/.test(parBody.error_description || "")) return { parRefusedScopes: parBody.error_description };
  if (!par.ok) throw new Error(`PAR -> ${par.status} ${JSON.stringify(parBody)}`);

  // Follows Keycloak's own redirects (login actions); stops at a page or at
  // the redirect back to the client.
  const follow = async (res) => {
    for (let hops = 0; res.status >= 300 && res.status < 400 && hops < 5; hops++) {
      const next = new URL(res.headers.get("location"), oidc);
      if (next.origin !== new URL(oidc).origin) return res;
      res = await browse(next.href);
    }
    return res;
  };
  const post = (url, form) => browse(new URL(url, oidc).href, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form) });
  let res = await follow(await browse(`${oidc}/auth?${new URLSearchParams({ client_id: clientId, request_uri: parBody.request_uri })}`));
  let html = res.status === 200 ? await res.text() : "";
  if (!formAction(html)) throw new Error(`authorization endpoint -> ${res.status}, no login form`);
  res = await follow(await post(formAction(html), { username: env.DRILL_PSU_USERNAME, password: env.DRILL_PSU_PASSWORD, credentialId: "" }));
  if (res.status === 200) {
    html = await res.text();
    if (!/name="accept"/.test(html)) throw new Error("login did not reach the consent screen (wrong credentials or required actions?)");
    res = await follow(await post(formAction(html), { ...hidden(html), accept: "Yes" }));
  }
  const location = res.headers.get("location") || "";
  const back = new URL(location, env.TPP_REDIRECT_URI);
  if (back.searchParams.get("error")) throw new Error(`authorization error ${back.searchParams.get("error")}: ${back.searchParams.get("error_description") || ""}`);
  const code = new URL(location, env.TPP_REDIRECT_URI).searchParams.get("code");
  if (!code) throw new Error(`no authorization code (status ${res.status}, redirect ${location.split("?")[0]})`);

  const tokenUrl = `${oidc}/token`;
  const tok = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: proof("POST", tokenUrl) },
    body: new URLSearchParams({ ...clientAuth(), grant_type: "authorization_code", code, redirect_uri: env.TPP_REDIRECT_URI, code_verifier: verifier })
  });
  const body = await tok.json();
  if (!tok.ok) throw new Error(`token -> ${tok.status} ${JSON.stringify(body)}`);
  return { tokenType: body.token_type, claims: decodeJwt(body.access_token), dpopJkt: jwkThumbprint(dpopJwk) };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const env = process.env;
    for (const k of ["KEYCLOAK_URL", "TPP_CLIENT_ID", "TPP_PRIVATE_JWK_FILE", "TPP_KID", "TPP_REDIRECT_URI", "DRILL_PSU_USERNAME", "DRILL_PSU_PASSWORD"]) if (!env[k]) throw new Error(`${k} is required`);
    const result = await drill(env);
    const expectPayments = env.DRILL_EXPECT_PAYMENTS === undefined ? undefined : env.DRILL_EXPECT_PAYMENTS === "true";
    const scope = (env.DRILL_SCOPE || "openid payments").split(" ");
    if (result.parRefusedScopes) {
      // Keycloak refuses a scope the client does not carry at PAR already.
      if (expectPayments === false && scope.includes("payments")) {
        console.log(`tpp-token-drill: OK (payments refused at PAR: ${result.parRefusedScopes})`);
        process.exit(0);
      }
      throw new Error(`PAR refused: ${result.parRefusedScopes}`);
    }
    const { tokenType, claims, dpopJkt } = result;
    const errors = tppTokenErrors(claims, { clientId: env.TPP_CLIENT_ID, expectPayments, dpopJkt });
    if (tokenType !== "DPoP") errors.push(`token_type is ${tokenType}, expected DPoP`);
    console.log(JSON.stringify({ token_type: tokenType, azp: claims.azp, fbx_client_type: claims.fbx_client_type, scope: claims.scope, aud: claims.aud, cnf_jkt_matches: claims.cnf?.jkt === dpopJkt }));
    if (errors.length) {
      for (const e of errors) console.error(`tpp-token-drill: ${e}`);
      process.exit(1);
    }
    console.log("tpp-token-drill: OK");
  } catch (e) {
    console.error(`tpp-token-drill: FAILED: ${e.message}`);
    process.exit(1);
  }
}
