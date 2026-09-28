// Adversarial expectation exporter.
//
// export_expect.mjs only builds probes out of a fingerprint's own fields, so
// almost every probe matches a fingerprint and the *fallback* paths stay
// untested. This exporter attacks the gaps:
//
//   A. Bare model keys: {modelID: key} with no manufacturer/date/sw. This
//      exercises "no fingerprint matched -> first zigbeeModel candidate" and
//      the exact-vs-normalized key split.
//   B. Ambiguous keys x every manufacturerName that appears anywhere in that
//      key's candidate set, with all other identity fields stripped. This
//      exercises the candidate ordering when several definitions share a
//      modelID but only some declare a fingerprint.
//   C. Key variants: the raw key plus its NUL/whitespace-normalized form.
//
// Output is the same NUL-safe TSV contract as export_expect.mjs.
import fs from 'node:fs';

const devMod = await import('zigbee-herdsman-converters/devices/index');
const defs = devMod.default?.default || devMod.default || devMod.definitions || [];
const zhc = await import('zigbee-herdsman-converters');
zhc.setLogger({debug(){},info(){},warn(){},error(){},log(){}});

const indexUrl = new URL('../node_modules/zigbee-herdsman-converters/dist/models-index.json',
                         import.meta.url);
const modelsIndex = JSON.parse(fs.readFileSync(indexUrl, 'utf8'));

function normalizeModelKey(value) {
  return String(value || '').replace(/\0(.|\n)*$/g, '').trim().toLowerCase();
}

// Collect, per model key, the manufacturer names of its candidate definitions.
const mfgByKey = new Map();
for (const [key, entries] of Object.entries(modelsIndex)) {
  const names = new Set();
  for (const [moduleName, index] of entries) {
    const def = defs.find((d) => d.model && false); // placeholder, resolved below
    void def;
    void moduleName;
    void index;
  }
  mfgByKey.set(key, names);
}

// Resolve definitions per key using the official loader so candidate sets are
// exactly what ZHC sees.
async function candidatesFor(key) {
  // getFromIndex is not exported; reproduce it through findByDevice probing is
  // not possible either. Instead walk the index and load the modules.
  const entries = modelsIndex[key] || [];
  const out = [];
  for (const [moduleName, index] of entries) {
    const mod = await import(`../node_modules/zigbee-herdsman-converters/dist/devices/${moduleName}`);
    const list = mod.definitions || mod.default?.definitions || mod.default || [];
    if (list[index]) out.push(list[index]);
  }
  return out;
}

const rows = [];
const seen = new Set();

function push(row) {
  const sig = JSON.stringify([row.modelID, row.manufacturerName, row.expected]);
  if (seen.has(sig)) return;
  seen.add(sig);
  rows.push(row);
}

async function probe(modelID, manufacturerName, tag) {
  let expected = null;
  try {
    const r = await zhc.findByDevice({
      ieeeAddr: '0x0000000000000001',
      modelID,
      manufacturerName: manufacturerName || '',
      endpoints: [],
    });
    if (r) expected = r.model;
  } catch (e) {
    expected = 'ERR:' + e.message;
  }
  push({
    modelID, manufacturerName,
    manufacturerID: 0, dateCode: '', softwareBuildID: '',
    hardwareVersion: -1, applicationVersion: -1, stackVersion: -1, zclVersion: -1,
    powerSource: 255, type: '', endpoints: [], expected, tag,
  });
}

const keys = Object.keys(modelsIndex);
console.error(`adversarial: ${keys.length} model keys`);

for (const key of keys) {
  const bare = key;
  const normalized = normalizeModelKey(key);
  // A. bare key, no manufacturer
  await probe(bare, '', 'bare');
  // C. normalized variant when it differs (tests exact-vs-normalized split)
  if (normalized && normalized !== bare) await probe(normalized, '', 'normalized');
  if (!normalized) continue;

  // B. every manufacturerName declared by this key's candidates
  const cands = await candidatesFor(key);
  const names = new Set();
  for (const d of cands) {
    for (const fp of (d.fingerprint || [])) {
      const n = fp.manufacturerName;
      if (typeof n === 'string' && n) names.add(n);
    }
  }
  for (const n of names) {
    await probe(bare, n, 'keyXmfg');
    if (normalized !== bare) await probe(normalized, n, 'keyXmfgNorm');
  }
}

const hex = (v) => {
  if (v === undefined || v === null) return '-';
  const s = String(v);
  if (s.length === 0) return '-';
  return Buffer.from(s, 'utf8').toString('hex');
};
const lines = rows.map((r) => [
  hex(r.modelID), hex(r.manufacturerName),
  String(r.manufacturerID), hex(r.dateCode), hex(r.softwareBuildID),
  String(r.hardwareVersion), String(r.applicationVersion),
  String(r.stackVersion), String(r.zclVersion), String(r.powerSource),
  r.type || '-', hex(r.expected), hex(JSON.stringify(r.endpoints || [])),
].join('\t'));

const outTsv = process.env.Z2M_EXPECT_TSV || '/tmp/adversarial.tsv';
fs.writeFileSync(outTsv, lines.join('\n') + '\n');
const unmatched = rows.filter((r) => r.expected === null).length;
const byTag = {};
for (const r of rows) byTag[r.tag] = (byTag[r.tag] || 0) + 1;
console.error(`adversarial rows=${rows.length} official_unmatched=${unmatched} tags=${JSON.stringify(byTag)}`);
