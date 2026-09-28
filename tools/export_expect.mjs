// Differential test data exporter.
//
// For every official ZHC definition (all device categories, not just
// switches), synthesize the device reports that definition declares via its
// fingerprints and zigbeeModel entries, then ask the *official* resolver what
// it selects. The resulting JSON is the ground truth the C++ matcher must
// reproduce exactly.
import fs from 'node:fs';

const devMod = await import('zigbee-herdsman-converters/devices/index');
const defs = devMod.default?.default || devMod.default || devMod.definitions || [];
const zhc = await import('zigbee-herdsman-converters');
zhc.setLogger({ debug(){}, info(){}, warn(){}, error(){}, log(){} });

function fieldOr(fp, key, dflt) {
  const v = fp[key];
  return v === undefined ? dflt : v;
}

function buildDevice(def, src) {
  let modelID, manufacturerName = '', manufacturerID, dateCode = '',
      softwareBuildID = '', hardwareVersion = -1, applicationVersion = -1,
      stackVersion = -1, zclVersion = -1, powerSource = 0xFF, type;
  let endpoints = [];
  if (src.kind === 'fp') {
    const fp = def.fingerprint[src.idx];
    if (fp.endpoints) {
      endpoints = fp.endpoints.map((e) => ({
        ID: e.ID,
        deviceID: e.deviceID,
        profileID: e.profileID,
        inputClusters: e.inputClusters ? e.inputClusters.slice() : [],
        outputClusters: e.outputClusters ? e.outputClusters.slice() : [],
      }));
    }
    modelID = fp.modelID;
    manufacturerName = fp.manufacturerName || '';
    manufacturerID = fp.manufacturerID;
    dateCode = fp.dateCode || '';
    softwareBuildID = fp.softwareBuildID || '';
    hardwareVersion = fieldOr(fp, 'hardwareVersion', -1);
    applicationVersion = fieldOr(fp, 'applicationVersion', -1);
    stackVersion = fieldOr(fp, 'stackVersion', -1);
    zclVersion = fieldOr(fp, 'zclVersion', -1);
    powerSource = fieldOr(fp, 'powerSource', 0xFF);
    type = fp.type;
  } else {
    modelID = def.zigbeeModel[src.idx];
  }
  if (modelID === undefined || modelID === null) return null;
  return {
    modelID, manufacturerName, manufacturerID, dateCode, softwareBuildID,
    hardwareVersion, applicationVersion, stackVersion, zclVersion,
    powerSource, type, endpoints,
  };
}

const rows = [];
for (const def of defs) {
  const sources = [];
  if (def.fingerprint) {
    for (let k = 0; k < def.fingerprint.length; k++) sources.push({kind: 'fp', idx: k});
  }
  if (def.zigbeeModel) {
    for (let k = 0; k < def.zigbeeModel.length; k++) sources.push({kind: 'zm', idx: k});
  }
  for (const src of sources) {
    const d = buildDevice(def, src);
    if (!d) continue;
    let expected = null;
    try {
      const eps = d.endpoints.map((e) => ({...e}));
      const r = await zhc.findByDevice({
        ieeeAddr: '0x0000000000000001',
        modelID: d.modelID,
        manufacturerName: d.manufacturerName,
        manufacturerID: d.manufacturerID,
        dateCode: d.dateCode,
        softwareBuildID: d.softwareBuildID,
        hardwareVersion: d.hardwareVersion,
        applicationVersion: d.applicationVersion,
        stackVersion: d.stackVersion,
        zclVersion: d.zclVersion,
        powerSource: d.powerSource,
        type: d.type,
        endpoints: eps,
        getEndpoint(id) { return eps.find((e) => e.ID === id); },
      });
      if (r) expected = r.model;
    } catch (e) {
      expected = 'ERR:' + e.message;
    }
    rows.push({...d, expected, declaredModel: def.model});
  }
}

const outJson = process.env.Z2M_EXPECT_JSON || '/tmp/expect.json';
fs.writeFileSync(outJson, JSON.stringify(rows));

// NUL-safe line protocol for the C++ differential harness.
// Every string field is hex-encoded; '-' means empty.
const hex = (v) => {
  if (v === undefined || v === null) return '-';
  const s = String(v);
  if (s.length === 0) return '-';
  return Buffer.from(s, 'utf8').toString('hex');
};
const lines = rows.map(r => [
  hex(r.modelID), hex(r.manufacturerName),
  String(r.manufacturerID === undefined || r.manufacturerID === null ? 0 : r.manufacturerID),
  hex(r.dateCode), hex(r.softwareBuildID),
  String(r.hardwareVersion), String(r.applicationVersion),
  String(r.stackVersion), String(r.zclVersion),
  String(r.powerSource === undefined || r.powerSource === null ? 255 : r.powerSource),
  r.type || '-',
  hex(r.expected),
  hex(JSON.stringify(r.endpoints || [])),
].join('\t'));
const outTsv = process.env.Z2M_EXPECT_TSV || '/tmp/expect.tsv';
fs.writeFileSync(outTsv, lines.join('\n') + '\n');
const unmatched = rows.filter(r => r.expected === null).length;
const mismatched = rows.filter(r => r.expected !== null && r.expected !== r.declaredModel).length;
console.log(`rows=${rows.length} official_unmatched=${unmatched} official_resolved_elsewhere=${mismatched}`);
