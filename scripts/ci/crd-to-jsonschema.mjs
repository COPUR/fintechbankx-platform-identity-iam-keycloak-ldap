#!/usr/bin/env node
// Converts CustomResourceDefinition files into kubeconform JSON schemas
// ({kind}-{group}-{version}.json, lower-case kind) so CRs are validated against
// the exact pinned operator version, not a moving community catalog.
// Objects that declare properties but no additionalProperties are closed
// (additionalProperties: false), matching kubeconform -strict semantics.
//
// usage: node scripts/ci/crd-to-jsonschema.mjs <out-dir> <crd.yaml>...
import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";

const [outDir, ...files] = process.argv.slice(2);
if (!outDir || files.length === 0) {
  console.error("usage: crd-to-jsonschema.mjs <out-dir> <crd.yaml>...");
  process.exit(2);
}

function close(schema) {
  if (!schema || typeof schema !== "object") return schema;
  if (Array.isArray(schema)) return schema.map(close);
  const out = {};
  for (const [k, v] of Object.entries(schema)) out[k] = typeof v === "object" ? close(v) : v;
  if (out.properties && out.additionalProperties === undefined && !out["x-kubernetes-preserve-unknown-fields"]) {
    out.additionalProperties = false;
  }
  return out;
}

fs.mkdirSync(outDir, { recursive: true });
let written = 0;
for (const file of files) {
  for (const doc of YAML.parseAllDocuments(fs.readFileSync(file, "utf8"))) {
    const crd = doc.toJSON();
    if (!crd || crd.kind !== "CustomResourceDefinition") continue;
    const group = crd.spec.group;
    const kind = crd.spec.names.kind.toLowerCase();
    for (const v of crd.spec.versions) {
      const schema = close(structuredClone(v.schema.openAPIV3Schema));
      // apiVersion/kind/metadata are validated by kubeconform itself.
      schema.properties = { ...schema.properties, apiVersion: { type: "string" }, kind: { type: "string" }, metadata: { type: "object" } };
      const name = `${kind}-${group}-${v.name}.json`;
      fs.writeFileSync(path.join(outDir, name), JSON.stringify(schema));
      written += 1;
    }
  }
}
console.log(`crd-to-jsonschema: wrote ${written} schema(s) to ${outDir}`);
