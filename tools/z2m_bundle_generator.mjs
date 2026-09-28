#!/usr/bin/env node
/**
 * Z2M -> ESP32 Converter Extractor & IR v5 Generator
 * Compatible with latest zigbee-herdsman-converters
 * Uses prepareDefinition() to fully expand modernExtend, fromZigbee, toZigbee,
 * configure, fingerprint, endpoints, and Tuya DP profiles.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

let legacyTuya = null;
try {
  legacyTuya = await import('zigbee-herdsman-converters/lib/legacy');
} catch {}


const outDir = process.argv[2] || 'build_ir';
fs.mkdirSync(outDir, { recursive: true });

// Import ZHC core modules
const zhc = await import('zigbee-herdsman-converters');
const DECLARATIVE_FROM_ZIGBEE_KEYS = new Set([
  // Attribute converters represented by the generic cluster/attribute IR.
  'linkquality_from_basic', 'battery', 'temperature', 'device_temperature',
  'humidity', 'pm25', 'flow', 'soil_moisture', 'pressure', 'co2',
  'occupancy', 'brightness', 'color_colortemp', 'metering',
  'electrical_measurement', 'gas_metering', 'on_off',
  'on_off_force_multiendpoint', 'on_off_skip_duplicate_transaction',
  'ias_no_alarm', 'ias_siren', 'ias_water_leak_alarm_1',
  'ias_water_leak_alarm_1_report', 'ias_vibration_alarm_1',
  'ias_gas_alarm_1', 'ias_gas_alarm_2', 'ias_smoke_alarm_1',
  'ias_contact_alarm_1', 'ias_contact_alarm_1_report',
  'ias_carbon_monoxide_alarm_1', 'ias_carbon_monoxide_alarm_1_gas_alarm_2',
  'ias_sos_alarm_2', 'ias_occupancy_alarm_1',
  'ias_occupancy_alarm_1_report', 'ias_occupancy_alarm_2',
  'ias_alarm_only_alarm_1', 'ias_occupancy_only_alarm_2',
  'cover_position_tilt', 'cover_position_via_brightness',
  'cover_state_via_onoff', 'curtain_position_analog_output',
  // Command-event converters implemented by generateCommandEventIR().
  'command_store', 'command_recall', 'command_panic', 'command_arm',
  'command_cover_stop', 'command_cover_open', 'command_cover_close',
  'command_on', 'command_off', 'command_off_with_effect', 'command_toggle',
  'command_move_to_level', 'command_move', 'command_step', 'command_stop',
  'command_move_color_temperature', 'command_stop_move_step',
  'command_step_color_temperature',
  'command_enhanced_move_to_hue_and_saturation',
  'command_move_to_hue_and_saturation', 'command_step_hue',
  'command_step_saturation', 'command_color_loop_set',
  'command_move_to_color_temp', 'command_move_to_color',
  'command_move_hue', 'command_move_to_saturation', 'command_move_to_hue',
  'command_emergency', 'command_on_state', 'command_off_state',
  'ewelink_action', 'command_status_change_notification_action',
  'ignore_command_on', 'ignore_command_off', 'ignore_command_off_with_effect',
  'ignore_command_step', 'ignore_command_stop',
  'ignore_iaszone_statuschange',
]);

function declarativeFromZigbeeKey(fz) {
  if (!fz || typeof fz.convert !== 'function') return null;
  for (const [key, candidate] of Object.entries(zhc.fromZigbee || {})) {
    if (!DECLARATIVE_FROM_ZIGBEE_KEYS.has(key) || !candidate) continue;
    if (candidate === fz || candidate.convert === fz.convert) return key;
  }
  return null;
}

function extractBatterySemantics(prep, exposes, clusterIds) {
  const properties = new Set((Array.isArray(exposes) ? exposes : [])
    .map(exp => String(exp && exp.property || '').toLowerCase())
    .filter(Boolean));
  const hasPowerCfg = clusterIds.has(0x0001);
  const batteryMeta = prep && prep.meta && prep.meta.battery && typeof prep.meta.battery === 'object'
    ? prep.meta.battery : {};
  const source = (Array.isArray(prep && prep.fromZigbee) ? prep.fromZigbee : [])
    .map(fz => String(fz && fz.convert || ''))
    .join(' ')
    .replace(/\s+/g, ' ');
  const hasBatteryConverter = source.includes('batteryPercentageRemaining') ||
    source.includes('batteryVoltage') || source.includes('batteryAlarmState');
  const enabled = hasPowerCfg && (hasBatteryConverter || properties.has('battery') ||
    properties.has('voltage') || properties.has('battery_low'));
  if (!enabled) return null;

  const voltageToPercentage = batteryMeta.voltageToPercentage;
  let curve = 0;
  let minVoltage = 0;
  let maxVoltage = 0;
  let voltageOffset = 0;
  if (voltageToPercentage === '3V_2100') {
    curve = 2;
  } else if (voltageToPercentage === '3V_1500_2800') {
    curve = 3;
  } else if (voltageToPercentage && typeof voltageToPercentage === 'object') {
    curve = 1;
    minVoltage = Number(voltageToPercentage.min) || 0;
    maxVoltage = Number(voltageToPercentage.max) || 0;
    voltageOffset = Number(voltageToPercentage.vOffset) || 0;
  }

  let dropPercentageValue = 0;
  let dropVoltageThreshold = 0;
  const exceptions = [];
  if (source.includes('batteryPercentageRemaining === 200') && source.includes('batteryVoltage < 30')) {
    dropPercentageValue = 200;
    dropVoltageThreshold = 30;
    const exceptionMatch = source.match(/\["([^"]+)"\]\.includes\(meta\.device\.manufacturerName\)/);
    if (exceptionMatch) exceptions.push(exceptionMatch[1]);
  }

  return {
    enabled: true,
    percentage: properties.has('battery'),
    voltage: properties.has('voltage'),
    lowStatus: properties.has('battery_low'),
    dontDividePercentage: batteryMeta.dontDividePercentage === true,
    curve,
    minVoltage,
    maxVoltage,
    voltageOffset,
    dropPercentageValue,
    dropVoltageThreshold,
    exceptions,
  };
}

function auditFromZigbeeCoverage(prep, category) {
  const missing = [];
  for (const fz of (Array.isArray(prep && prep.fromZigbee) ? prep.fromZigbee : [])) {
    if (declarativeFromZigbeeKey(fz)) continue;
    const source = String(fz && fz.convert || '').replace(/\s+/g, ' ');
    let reason = 'unmodeled_from';
    if (!fz || typeof fz.convert !== 'function') reason = 'missing_convert';
    else if (fz.convert.constructor && fz.convert.constructor.name === 'AsyncFunction') reason = 'async_from';
    else if (/\b(?:globalStore|setInterval|setTimeout|Date\.now|clearInterval|clearTimeout)\b/.test(source)) reason = 'stateful_from';
    missing.push({reason, source: source.slice(0, 200)});
    converterCoverageAudit.push({
      model: String(prep.model || ''),
      vendor: String(prep.vendor || ''),
      category: String(category || ''),
      reason,
      source: source.slice(0, 200),
    });
  }
  return missing;
}
const devMod = await import('zigbee-herdsman-converters/devices/index');
const defs = devMod.default?.default || devMod.default || devMod.definitions || [];

// Official candidate order used by ZHC's MODELS_INDEX fallback.
let modelsIndex = {};
try {
  modelsIndex = JSON.parse(fs.readFileSync(new URL('../node_modules/zigbee-herdsman-converters/dist/models-index.json', import.meta.url), 'utf8'));
} catch {}

const moduleDefinitionCache = new Map();
async function getModuleDefinitions(moduleName) {
  if (moduleDefinitionCache.has(moduleName)) return moduleDefinitionCache.get(moduleName);
  try {
    const url = new URL(`../node_modules/zigbee-herdsman-converters/dist/devices/${moduleName}`, import.meta.url);
    const mod = await import(url.href);
    const list = mod.definitions || mod.default?.definitions || mod.default || [];
    moduleDefinitionCache.set(moduleName, list);
    return list;
  } catch {
    moduleDefinitionCache.set(moduleName, []);
    return [];
  }
}

const modelPriorities = {};
// DPs whose official inbound converter cannot be reproduced by the
// declarative rule set. Written to z2m_vm_unsupported.ndjson for auditing.
const inboundAudit = [];
// Every official fromZigbee converter that is not represented by the
// declarative IR path. Tuya DPs are audited separately at their call
// sites; this list also covers non-Tuya vendor closures, async code,
// timers/globalStore, and converters whose output is not fully modeled.
const converterCoverageAudit = [];
const definitionModelRanks = new Map();
function normalizeModelKey(value) {
  return String(value || '').replace(/\0(.|\n)*$/g, '').trim().toLowerCase();
}


for (const [model, entries] of Object.entries(modelsIndex)) {
  const rawKey = String(model || '').toLowerCase();
  const key = normalizeModelKey(rawKey);
  // MODELS_INDEX may contain keys that normalize to the empty string
  // (for example an all-NUL modelID). ZHC still looks up the raw key
  // first, so those definitions must remain addressable.
  if (!rawKey) continue;
  const rankByDefinition = new Map();
  for (let rank = 0; rank < entries.length; rank++) {
    const [moduleName, index] = entries[rank];
    const definitions = await getModuleDefinitions(moduleName);
    const definition = definitions[index];
    if (definition && !rankByDefinition.has(definition)) rankByDefinition.set(definition, rank);
  }
  // ZHC first looks up the exact lower-cased modelID and only falls back
  // to the NUL/whitespace-normalized key when that exact key is absent.
  // Preserve both lookup classes so candidates are never merged across
  // distinct official keys.
  if (!modelPriorities[rawKey]) modelPriorities[rawKey] = rankByDefinition;
  if (key && !modelPriorities[key]) modelPriorities[key] = rankByDefinition;
  for (const [definition, rank] of rankByDefinition) {
    let ranks = definitionModelRanks.get(definition);
    if (!ranks) {
      ranks = new Map();
      definitionModelRanks.set(definition, ranks);
    }
    if (!ranks.has(rawKey) || rank < ranks.get(rawKey)) ranks.set(rawKey, rank);
    if (key && (!ranks.has(key) || rank < ranks.get(key))) ranks.set(key, rank);
  }
}
const definitionExactModelKeys = new Map();
const definitionNormalizedModelKeys = new Map();

function addDefinitionKey(map, definition, value) {
  if (!definition || !value) return;
  let keys = map.get(definition);
  if (!keys) {
    keys = new Set();
    map.set(definition, keys);
  }
  keys.add(value);
}

for (const [model, entries] of Object.entries(modelsIndex)) {
  const rawKey = String(model || '').toLowerCase();
  const key = normalizeModelKey(rawKey);
  if (!rawKey) continue;
  for (const [moduleName, index] of entries) {
    const definitions = await getModuleDefinitions(moduleName);
    const definition = definitions[index];
    addDefinitionKey(definitionExactModelKeys, definition, rawKey);
    if (key) addDefinitionKey(definitionNormalizedModelKeys, definition, key);
  }
}

const NO_MODEL_RANK = 0x7FFF;
function rankForModelDefinition(model, definition) {
  const rawKey = String(model || '').toLowerCase();
  const normalizedKey = normalizeModelKey(rawKey);
  const ranks = modelPriorities[rawKey] || modelPriorities[normalizedKey];
  if (!ranks) return NO_MODEL_RANK;
  const rank = ranks.get(definition);
  return rank === undefined ? NO_MODEL_RANK : rank;
}

function declaredModelKeys(prep, d) {
  const keys = new Set();
  const add = value => {
    const raw = String(value ?? '');
    if (raw) keys.add(raw);
  };
  if (Array.isArray(prep?.zigbeeModel)) prep.zigbeeModel.forEach(add);
  if (Array.isArray(d?.zigbeeModel)) d.zigbeeModel.forEach(add);
  return keys;
}

function buildModelPriorityMap(modelKeys, definition) {
  const result = {};
  for (const modelKey of modelKeys) {
    const rank = rankForModelDefinition(modelKey, definition);
    if (rank !== NO_MODEL_RANK) result[modelKey] = rank;
  }
  return result;
}

function buildFingerprintCandidateRanks(fpModel, declaredModels, definition) {
  const result = {};
  const keys = fpModel ? [fpModel] : Array.from(declaredModels);
  for (const key of keys) {
    const rank = rankForModelDefinition(key, definition);
    if (rank !== NO_MODEL_RANK) result[key] = rank;
  }
  return result;
}

let zhcPackageVersion = 'unknown';
try {
  const pkg = JSON.parse(fs.readFileSync(new URL('../node_modules/zigbee-herdsman-converters/package.json', import.meta.url), 'utf8'));
  zhcPackageVersion = String(pkg.version || 'unknown');
} catch {}

let zh = null;
try {
  zh = await import('zigbee-herdsman');
} catch (e) {
  // Optional fallback
}

let tuya = null;
try {
  tuya = await import('zigbee-herdsman-converters/lib/tuya');
} catch (e) {}

console.log(`[IR Extractor] Loaded ${defs.length} definitions from zigbee-herdsman-converters.`);

// Cluster name to uint16 ID mapping
const CLUSTER_NAME_TO_ID = {

  genBasic: 0x0000,

  genPowerCfg: 0x0001,
  genDeviceTempCfg: 0x0002,
  genIdentify: 0x0003,
  genGroups: 0x0004,
  genScenes: 0x0005,
  genOnOff: 0x0006,
  genOnOffSwitchCfg: 0x0007,
  genLevelCtrl: 0x0008,
  genAlarms: 0x0009,
  genTime: 0x000A,
  closuresDoorLock: 0x0101,
  closuresWindowCovering: 0x0102,
  hvacThermostat: 0x0201,
  hvacFanCtrl: 0x0202,
  hvacUserInterfaceCfg: 0x0204,
  lightingColorCtrl: 0x0300,
  lightingBallastCfg: 0x0301,
  msIlluminanceMeasurement: 0x0400,
  msIlluminanceLevelSensing: 0x0401,
  msTemperatureMeasurement: 0x0402,
  msPressureMeasurement: 0x0403,
  msFlowMeasurement: 0x0404,
  msRelativeHumidity: 0x0405,
  msOccupancySensing: 0x0406,
  msCO2: 0x040D,
  ssIasZone: 0x0500,
  ssIasAce: 0x0501,
  ssIasWd: 0x0502,
  seMetering: 0x0702,
  haElectricalMeasurement: 0x0B04,
  manuSpecificTuya: 0xEF00,
  manuSpecificLumi: 0xFCC0,
};

// ZCL cluster-specific command IDs used by the official fromZigbee
// command converters. Keep this table explicit: command IDs and attribute
// IDs often share numbers but have unrelated semantics.
// Official ZCL command names differ from their Zigbee2MQTT converter type
// names. Resolve IDs from the official cluster tables instead of keeping a
// hand-maintained global map: commandStop is 0x03 in genLevelCtrl but 0x02
// in closuresWindowCovering. A global map silently misroutes one of them.
function officialCommandId(clusterName, converterType) {
  const raw = String(converterType || '');
  if (!raw.startsWith('command')) return undefined;
  const commandName = raw.slice('command'.length);
  const cluster = zh && zh.Zcl && zh.Zcl.Clusters && zh.Zcl.Clusters[clusterName];
  if (!cluster) return undefined;
  for (const tableName of ['commands', 'commandsResponse']) {
    const table = cluster[tableName];
    if (!table) continue;
    for (const definition of Object.values(table)) {
      if (definition && typeof definition.ID === 'number' &&
          String(definition.name || '').toLowerCase() === commandName.toLowerCase()) {
        return definition.ID;
      }
    }
  }
  return undefined;
}

if (zh && zh.Zcl && zh.Zcl.Clusters) {
  for (const [name, cl] of Object.entries(zh.Zcl.Clusters)) {
    if (cl && typeof cl.ID === 'number') {
      CLUSTER_NAME_TO_ID[name] = cl.ID;
    }
  }
}

function resolveClusterId(cl) {
  if (typeof cl === 'number') return cl;
  if (!cl) return 0;
  if (typeof cl === 'string') {
    const trimmed = cl.trim();
    if (CLUSTER_NAME_TO_ID[trimmed] !== undefined) {
      return CLUSTER_NAME_TO_ID[trimmed];
    }
    if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
      return parseInt(trimmed, 16);
    }
    const parsed = parseInt(trimmed, 10);
    if (!isNaN(parsed)) return parsed;
  }
  return 0;
}

function cleanId(value) {
  return String(value || '').replace(/\0+$/g, '').trim();
}

function normalizeFingerprint(fp) {
  if (!fp || typeof fp !== 'object') return null;
  // ZHC compares these fields with strict equality. Preserve embedded or
  // trailing NUL bytes and surrounding whitespace exactly as declared.
  const modelID = String(fp.modelID ?? '');
  const manufacturerName = String(fp.manufacturerName ?? '');
  const endpoints = Array.isArray(fp.endpoints) ? fp.endpoints.map(ep => ({
    ID: Number(ep && ep.ID),
    profileID: ep && ep.profileID !== undefined ? Number(ep.profileID) : null,
    deviceID: ep && ep.deviceID !== undefined ? Number(ep.deviceID) : null,
    inputClusters: Array.isArray(ep && ep.inputClusters)
      ? ep.inputClusters.map(resolveClusterId)
      : null,
    outputClusters: Array.isArray(ep && ep.outputClusters)
      ? ep.outputClusters.map(resolveClusterId)
      : null,
  })).filter(ep => Number.isInteger(ep.ID) && ep.ID >= 0 && ep.ID <= 255) : null;
  return {
    modelID,
    manufacturerName,
    manufacturerCode: fp.manufacturerID ?? fp.manufacturerCode ?? null,
    type: fp.type || '',
    powerSource: fp.powerSource || '',
    softwareBuildID: fp.softwareBuildID || '',
    dateCode: fp.dateCode || '',
    applicationVersion: fp.applicationVersion === undefined ? null : Number(fp.applicationVersion),
    hardwareVersion: fp.hardwareVersion === undefined ? null : Number(fp.hardwareVersion),
    stackVersion: fp.stackVersion === undefined ? null : Number(fp.stackVersion),
    zclVersion: fp.zclVersion === undefined ? null : Number(fp.zclVersion),
    priority: Number.isFinite(Number(fp.priority)) ? Number(fp.priority) : 0,
    ieeeAddr: fp.ieeeAddr instanceof RegExp ? fp.ieeeAddr.source : (fp.ieeeAddr ? String(fp.ieeeAddr) : ''),
    endpoints,
    raw: {
      manufacturerID: fp.manufacturerID ?? fp.manufacturerCode ?? null,
      type: fp.type || '',
      powerSource: fp.powerSource || '',
      softwareBuildID: fp.softwareBuildID || '',
      dateCode: fp.dateCode || '',
      applicationVersion: fp.applicationVersion === undefined ? null : Number(fp.applicationVersion),
      hardwareVersion: fp.hardwareVersion === undefined ? null : Number(fp.hardwareVersion),
      stackVersion: fp.stackVersion === undefined ? null : Number(fp.stackVersion),
      zclVersion: fp.zclVersion === undefined ? null : Number(fp.zclVersion),
      priority: Number.isFinite(Number(fp.priority)) ? Number(fp.priority) : 0,
      ieeeAddr: fp.ieeeAddr instanceof RegExp ? fp.ieeeAddr.source : (fp.ieeeAddr ? String(fp.ieeeAddr) : ''),
      endpoints,
    },
  };
}

function hex16(num) {
  return '0x' + (num & 0xFFFF).toString(16).padStart(4, '0').toUpperCase();
}

// Probe an official fromZigbee converter with a synthetic message so the
// declarative extractor can follow the fields it actually publishes. This
// is deliberately limited to synchronous converters; async converters are
// handled conservatively by the caller.

let probeSequence = 1;

function buildProbeDevice(endpoints = {}, endpointId = 1, probeId = 1) {
  const endpointIds = sortedEndpointIds(endpoints);
  const effectiveIds = endpointIds.length > 0 ? endpointIds : [1];
  const inputClusters = [
    0x0000, 0x0001, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008,
    0x0101, 0x0102, 0x0201, 0x0300, 0x0400, 0x0402, 0x0405,
    0x0406, 0x0500, 0x0702, 0x0B04, 0xEF00,
  ];
  const eps = effectiveIds.map(ID => ({
    ID,
    deviceID: 5,
    profileID: 260,
    inputClusters: inputClusters.slice(),
    outputClusters: [],
  }));
  const device = {
    ieeeAddr: `0x00124b00${(probeId & 0xFFFFFFFF).toString(16).padStart(8, '0')}`,
    networkAddress: 0,
    manufacturerID: 0,
    manufacturerName: '',
    modelID: '',
    endpoints: eps,
    getEndpoint(id) { return this.endpoints.find(ep => ep.ID === id); },
    getClusterAttributeValue() { return undefined; },
  };
  for (const ep of eps) ep.getClusterAttributeValue = () => undefined;
  const endpoint = device.getEndpoint(endpointId) || eps[0];
  return {device, endpoint};
}

function normalizeProbeData(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return data;
  const normalized = {...data};
  for (const [key, value] of Object.entries(normalized)) {
    if (value === undefined) delete normalized[key];
  }
  return normalized;
}

function probeConverterFields(fz, clusterId, attributeId, definition = null,
                              endpointId = 1, endpoints = {}) {
  if (!fz || typeof fz.convert !== 'function') return null;
  if (fz.convert.constructor && fz.convert.constructor.name === 'AsyncFunction') return null;
  const probeId = probeSequence++;
  const {device, endpoint} = buildProbeDevice(endpoints, endpointId, probeId);
  const data = {};
  if (clusterId === 0x0006 && attributeId === 0x0000) data.onOff = 1;
  const msg = {
    endpoint,
    device,
    data,
    type: 'attributeReport',
    meta: {zclTransactionSequenceNumber: probeId & 0xFF, device},
  };

  // Command converters receive a msg.type such as commandOn and read
  // msg.data / msg.endpoint.ID. The synthetic endpoint already carries
  // the real endpoint id, so command probes use the same shape.
  if (typeof arguments[5] === 'string') {
    msg.type = arguments[5];
  }
  const model = definition || {};
  try {
    const result = fz.convert(model, msg, () => {}, {}, {device});
    if (!result || typeof result !== 'object') return null;
    return normalizeProbeData(result);
  } catch {
    return null;
  }
}

// Find a synchronous official genOnOff attribute converter that publishes a
// state-like field for onOff. Action-only command converters must not be
// turned into a fake relay state.

function officialOnOffInspection(prep, endpoints = {}) {
  const targets = new Map();
  const unsupported = [];
  const converters = Array.isArray(prep && prep.fromZigbee) ? prep.fromZigbee : [];
  // Official command converters receive the endpoint that sent the
  // command. Use 0 so runtime endpoint matching accepts any physical
  // endpoint while still retaining the final property mapping.
  const probeEndpointIds = [0];

  for (const fz of converters) {
    const clusters = Array.isArray(fz && fz.cluster) ? fz.cluster : [fz && fz.cluster];
    if (!clusters.some(cluster => resolveClusterId(cluster) === 0x0006)) continue;

    // This inspection is for attribute state converters. CommandOn/Off
    // converters (including command_on_state) belong to the command path
    // and must not create an attributeReport rule.
    const types = Array.isArray(fz.type) ? fz.type : [fz.type];
    const handlesAttribute = types.some(type =>
      type === 'attributeReport' || type === 'readResponse');
    if (!handlesAttribute) continue;

    // ignore_onoff_report intentionally consumes the report. It is
    // serialized as an IGNORE rule elsewhere and must not be audited as a
    // failed state converter.
    const source = String(fz && fz.convert || '').replace(/\s+/g, '');
    if (/^(?:async)?\([^)]*\)=>\{\}$/.test(source)) continue;

    let sawResult = false;
    for (const endpointId of probeEndpointIds) {
      const result = probeConverterFields(fz, 0x0006, 0x0000, prep, endpointId, endpoints);
      if (!result) continue;
      sawResult = true;
      for (const [key, value] of Object.entries(result)) {
        if (!/^(?:state|switch)(?:_|$)/.test(key)) continue;
        const normalized = canonicalStateProperty(key, endpoints);
        if (normalized.property !== 'state' &&
            !/^state_l[1-9][0-9]*$/.test(normalized.property)) continue;
        const stateValue = String(value ?? '').toUpperCase();
        if (stateValue !== 'ON' && stateValue !== 'OFF') continue;
        const endpoint = normalized.property === 'state'
          ? 0
          : (normalized.endpoint || endpointId || 0);
        if (!targets.has(normalized.property)) {
          targets.set(normalized.property, endpoint);
        } else if (normalized.property !== 'state' && endpoint &&
                   !targets.get(normalized.property)) {
          targets.set(normalized.property, endpoint);
        }
      }
    }
    if (!sawResult) {
      unsupported.push({
        cluster: '0x0006',
        property: 'state',
        reason: 'unprobeable_from',
        source: String(fz && fz.convert || '').slice(0, 200),
      });
    }
  }
  return {targets, unsupported};
}

function hasOfficialOnOffStateConverter(prep, endpoints = {}) {
  return officialOnOffInspection(prep, endpoints).targets.size > 0;
}


// A state expose may use state_l1/l2/l3/l4, state_left/center/right, or a
// named endpoint such as button_1. Normalize all of them to state_lN and
// attach the real endpoint, so runtime dispatch never has to guess.
function sortedEndpointIds(endpoints) {
  return [...new Set(Object.values(endpoints || {}).filter(v => typeof v === 'number' && v > 0))]
    .sort((a, b) => a - b);
}

function sortedEndpointEntries(endpoints) {
  return Object.entries(endpoints || {})
    .filter(([, id]) => typeof id === 'number' && id > 0)
    .sort(([aName, aId], [bName, bId]) => (aId - bId) || aName.localeCompare(bName));
}

// A bare numeric suffix on a logical property (momentary_2, week_program_3)
// is not a physical endpoint. Only explicit endpoint-map entries count.
function resolveExplicitEndpoint(endpointName, endpoints) {
  if (endpointName === undefined || endpointName === null || endpointName === '') return 0;
  const key = String(endpointName);
  return endpoints && typeof endpoints[key] === 'number' ? endpoints[key] : 0;
}

function resolveEndpoint(endpointName, endpoints) {
  if (endpointName === undefined || endpointName === null || endpointName === '') return 0;
  const key = String(endpointName);
  if (endpoints && typeof endpoints[key] === 'number') return endpoints[key];
  if (/^[0-9]+$/.test(key)) return Number(key);
  return 0;
}

function canonicalStateProperty(prop, endpoints) {
  const raw = String(prop || '');
  const match = raw.match(/^(state|switch)(?:_?(.+))?$/i);
  if (!match) return { property: raw, endpoint: 0 };
  const suffix = match[2] || '';
  let endpoint = resolveEndpoint(suffix, endpoints);
  let gang = 0;
  const lMatch = suffix.match(/^l([1-9][0-9]*)$/i);
  const nMatch = suffix.match(/^([1-9][0-9]*)$/);
  if (lMatch) {
    gang = Number(lMatch[1]);
    if (!endpoint) endpoint = gang;
  } else if (nMatch) {
    gang = Number(nMatch[1]);
    if (!endpoint) endpoint = gang;
  } else if (endpoint) {
    const index = sortedEndpointIds(endpoints).indexOf(endpoint);
    if (index >= 0) gang = index + 1;
  }
  if (!endpoint && !suffix) {
    const ids = sortedEndpointIds(endpoints);
    if (ids.length === 1) endpoint = ids[0];
  }
  const explicitGang = gang > 0;
  const multiEndpoint = sortedEndpointIds(endpoints).length > 1;
  return {
    property: (explicitGang || multiEndpoint) && gang > 0 ? `state_l${gang}` : raw,
    endpoint: endpoint || 0
  };
}
function canonicalStateExpose(exp, endpoints) {
  const raw = String(exp && exp.property || 'state');
  const endpointName = exp && exp.endpoint !== undefined ? String(exp.endpoint) : '';
  const normalized = canonicalStateProperty(raw, endpoints);
  let endpoint = resolveEndpoint(endpointName, endpoints) || normalized.endpoint;
  let gang = 0;
  const suffix = (raw.match(/^(?:state|switch)_?(.*)$/i) || [])[1] || '';
  const lMatch = suffix.match(/^l([1-9][0-9]*)$/i);
  const nMatch = suffix.match(/^([1-9][0-9]*)$/);
  if (lMatch) gang = Number(lMatch[1]);
  else if (nMatch) gang = Number(nMatch[1]);
  // Numeric suffixes are already 1-based gang numbers. Named suffixes
  // (left/right/center, lights/high/low) must use the endpoint map order.
  if (gang <= 0 && endpoint) {
    const index = sortedEndpointIds(endpoints).indexOf(endpoint);
    if (index >= 0) gang = index + 1;
  }
  if (gang <= 0 && !suffix && endpoint) gang = 1;
  return {
    property: (suffix || sortedEndpointIds(endpoints).length > 1) && gang > 0 ? `state_l${gang}` : normalized.property,
    endpoint: endpoint || normalized.endpoint || 0
  };
}

function statePropertyForEndpoint(endpoints, endpointId) {
  const ids = sortedEndpointIds(endpoints);
  const index = ids.indexOf(endpointId);
  return index >= 0 ? `state_l${index + 1}` : 'state';
}

// Official endpoint naming helper. ZHC only appends an endpoint suffix when
// meta.multiEndpoint is enabled and the property is not in multiEndpointSkip.
// An expose may already carry the final endpoint-specific property, so do
// not append the same suffix twice.
function endpointProperty(prop, endpointName, meta) {
  const raw = String(prop || '');
  const skip = Array.isArray(meta && meta.multiEndpointSkip)
    ? meta.multiEndpointSkip.map(String)
    : [];
  if (!meta || meta.multiEndpoint !== true || !endpointName || skip.includes(raw)) {
    return raw;
  }
  const suffix = String(endpointName);
  if (!suffix || raw === suffix || raw.endsWith(`_${suffix}`)) return raw;
  return `${raw}_${suffix}`;
}

function endpointNameForId(endpoints, endpointId) {
  if (!endpoints || endpointId === undefined || endpointId === null || endpointId === 0) return '';
  for (const [name, id] of Object.entries(endpoints)) {
    if (Number(id) === Number(endpointId)) return String(name);
  }
  return String(endpointId);
}

function routePropertyForExpose(exp, endpoints, meta) {
  const raw = String(exp && exp.property || '');
  const endpointName = exp && exp.endpoint !== undefined && exp.endpoint !== null ? String(exp.endpoint) : '';
  const endpointId = resolveEndpoint(endpointName, endpoints);
  return { property: endpointProperty(raw, endpointName, meta), endpoint: endpointId };
}

function propertyMatchesExpose(exposeProperty, baseProperty) {
  const actual = String(exposeProperty || '');
  const base = String(baseProperty || '');
  return actual === base || actual.startsWith(`${base}_`);
}

// Resolve the public property and physical endpoint for standard ZCL rules.
// ZHC exposes are already expanded by modernExtend: exposeEndpoints()
// attaches the endpoint name, while postfixWithEndpointName() changes the
// published property. Some custom definitions carry both forms, so avoid
// appending the same endpoint suffix twice.
function standardExposeRoutes(exposes, endpoints, meta, baseProperties) {
  const bases = Array.isArray(baseProperties) ? baseProperties : [baseProperties];
  const routes = [];
  const seen = new Set();
  for (const exp of exposes) {
    const raw = String(exp && exp.property || '');
    if (!bases.some(base => propertyMatchesExpose(raw, base))) continue;
    const route = routePropertyForExpose(exp, endpoints, meta);
    if (!route.property) continue;
    const key = `${route.property}:${route.endpoint}`;
    if (seen.has(key)) continue;
    seen.add(key);
    routes.push(route);
  }
  return routes;
}

function defaultRouteForProperty(property, endpoints, meta) {
  const prop = String(property || '');
  const endpointIds = sortedEndpointIds(endpoints);
  const endpoint = endpointIds.length === 1 ? endpointIds[0] : 0;
  return { property: endpointProperty(prop, endpointNameForId(endpoints, endpoint), meta), endpoint };
}

// legacy.fz.tuya_switch predates meta.tuyaDatapoints. Its wire format is
// nevertheless Tuya DP: DP1..DP6 are relay states and multiEndpoint maps
// them to state_l1..state_l6 on one physical endpoint. Recover that table
// from the exposes so these devices do not get a bogus genOnOff rule.
function isLegacyTuyaSwitch(prep) {
  return Array.isArray(prep && prep.fromZigbee) && prep.fromZigbee.some(fz =>
    String(fz && fz.convert || '').includes('firstDpValue(msg, meta, "tuya_switch")')
  );
}

function extractLegacyTuyaSwitchDatapoints(prep) {
  if (!isLegacyTuyaSwitch(prep)) return [];
  const stateItems = stateExposes(parseExposes(prep.exposes));
  const dps = [];
  const seen = new Set();
  for (const exp of stateItems) {
    const raw = String(exp.property || 'state');
    const match = raw.match(/^(?:state|switch)_?(?:l)?([1-9][0-9]*)$/i);
    const dp = match ? Number(match[1]) : 1;
    if (dp < 1 || dp > 6 || seen.has(dp)) continue;
    seen.add(dp);
    dps.push({
      dp,
      target: match ? `state_l${dp}` : 'state',
      datatype: 'bool',
      scale: 1.0,
      offset: 0.0,
      map: null
    });
  }
  // A malformed/empty expose list must still preserve the one-gang DP1
  // behavior of legacy.fz.tuya_switch.
  if (dps.length === 0) {
    dps.push({ dp: 1, target: 'state', datatype: 'bool', scale: 1.0, offset: 0.0, map: null });
  }
  return dps;
}

function normalizeEnumValue(value) {
  return String(value ?? '').trim().toUpperCase();
}

// Door-lock detection must not treat child_lock, keypad_lockout or other
// configuration properties as proof that the device itself is a lock.
// ZHC encodes standard locks as an explicit Lock expose (type="lock"),
// while a few devices expose only state/lock_state with LOCK/UNLOCK values.
function hasLockExposeSemantics(exposes) {
  const list = Array.isArray(exposes) ? exposes : [];
  if (list.some(e => String(e && e.type || '').toLowerCase() === 'lock')) return true;
  const props = new Set(list.map(e => String(e && e.property || '').toLowerCase()));
  if (props.has('lock_state') || props.has('lock') || props.has('unlock')) return true;
  return list.some(e => {
    const prop = String(e && e.property || '').toLowerCase();
    if (prop !== 'state' && prop !== 'lock_state') return false;
    const on = normalizeEnumValue(e && e.value_on);
    const off = normalizeEnumValue(e && e.value_off);
    const lockish = value => value === 'LOCK' || value === 'LOCKED' || value === 'UNLOCK' || value === 'UNLOCKED';
    return lockish(on) || lockish(off);
  });
}

function hasStandardDoorLockConverter(prep) {
  return Array.isArray(prep && prep.fromZigbee) && prep.fromZigbee.some(fz => {
    const clusters = Array.isArray(fz && fz.cluster) ? fz.cluster : [fz && fz.cluster];
    return clusters.some(cluster => resolveClusterId(cluster) === 0x0101);
  });
}

// A converter that merely references closuresDoorLock may only decode a
// vendor-specific payload (Aqara ZNMS11/12/13). Standard lock reporting is
// only safe when the converter actually reads msg.data.lockState.
function hasStandardDoorLockStateConverter(prep) {
  return Array.isArray(prep && prep.fromZigbee) && prep.fromZigbee.some(fz => {
    const clusters = Array.isArray(fz && fz.cluster) ? fz.cluster : [fz && fz.cluster];
    if (!clusters.some(cluster => resolveClusterId(cluster) === 0x0101)) return false;
    return /(?:msg|data)\.data(?:\.lockState|\[['\"]lockState['\"]\])/.test(String(fz && fz.convert || ''));
  });
}

// Category classification
function classifyCategory(exposesList, descStr = '', clusterIds = new Set()) {
  const exposes = Array.isArray(exposesList) ? exposesList : [];
  const props = new Set(exposes.map(e => String(e && e.property || '').toLowerCase()).filter(Boolean));
  const types = new Set(exposes.map(e => String(e && e.type || '').toLowerCase()).filter(Boolean));
  const desc = String(descStr || '').toLowerCase();
  const hasProp = (...names) => names.some(name => props.has(name));
  const descHas = (...terms) => terms.some(term => desc.includes(term));

  // Action-only remotes and scene switches are not lights or relays.
  // Some of them bind/use genOnOff and genLevelControl only to emit
  // command events (action), so cluster presence alone must not decide
  // the category or expose a synthetic state.
  const hasAction = props.has('action');
  const hasStateSemantic = hasProp(
    'state', 'switch', 'brightness', 'color_temp', 'color_xy',
    'position', 'cover', 'lock_state',
    'occupied_heating_setpoint', 'current_heating_setpoint', 'system_mode'
  );
  if (hasAction && !hasStateSemantic) return 'remote_control';
  if (hasLockExposeSemantics(exposes)) return 'door_lock';
  if (clusterIds.has(0x0102) || types.has('cover')) return 'window_covering';
  if (clusterIds.has(0x0201) || types.has('climate') ||
      hasProp('occupied_heating_setpoint', 'current_heating_setpoint', 'local_temperature', 'system_mode') ||
      descHas('thermostat', 'radiator valve', 'trv', 'climate')) {
    return 'thermostat';
  }

  // A real lock must expose lock state/action semantics. Do not classify a
  // thermostat or switch merely because it has a child_lock expose.

  if (clusterIds.has(0x0300) || hasProp('color_xy', 'color_temp', 'hue', 'saturation', 'x', 'y')) return 'color_light';
  if (clusterIds.has(0x0008) || hasProp('brightness')) return 'dimmable_light';
  if (hasProp('water_leak', 'waterleak') || descHas('water leak', 'waterleak')) return 'water_leak_sensor';
  if (hasProp('smoke') || descHas('smoke detector', 'smoke alarm')) return 'smoke_sensor';
  if (clusterIds.has(0x0406) || hasProp('occupancy', 'presence', 'motion')) return 'occupancy_sensor';
  // IAS Alarm 2 (or a CO-specific converter) proves carbon-monoxide
  // semantics. Check it before generic gas because dual CO/gas alarms
  // expose both properties from the same zone-status word.
  if (hasProp('carbon_monoxide') || descHas('carbon monoxide', 'co alarm', 'co detector')) return 'carbon_monoxide_sensor';
  if (hasProp('gas', 'gas_leak') || descHas('gas detector', 'combustible gas')) return 'gas_sensor';
  if (hasProp('vibration') || descHas('vibration sensor', 'vibration alarm')) return 'vibration_sensor';
  if (hasProp('contact', 'door_state', 'window_state') || descHas('contact sensor', 'door sensor', 'window sensor')) return 'contact_sensor';
  if (clusterIds.has(0x0405) || hasProp('humidity')) return 'humidity_sensor';
  if (clusterIds.has(0x0400) || hasProp('illuminance', 'illuminance_lux')) return 'light_sensor';
  if (clusterIds.has(0x0402) || hasProp('temperature')) return 'temp_sensor';
  if (hasProp('outlet', 'plug', 'socket') || descHas('plug', 'outlet', 'socket')) return 'on_off_plugin_unit';
  if (clusterIds.has(0x0006) || hasProp('state', 'switch') || descHas('switch', 'relay')) return 'on_off_switch';
  return 'generic_device';
}

// Extract exposes properties
function parseExposes(rawExposes) {
  let list = [];
  if (typeof rawExposes === 'function') {
    try {
      list = rawExposes({ isDummyDevice: true }, {});
    } catch {
      list = [];
    }
  } else if (Array.isArray(rawExposes)) {
    list = rawExposes;
  }
  const result = [];
  function walk(item, inheritedEndpoint) {
    if (!item) return;
    const endpointName = item.endpoint !== undefined ? item.endpoint : inheritedEndpoint;
    if (Array.isArray(item.features)) {
      item.features.forEach(feature => walk(feature, endpointName));
    }
    // Composite color_xy exposes carry the feature set that tells us an
    // endpoint really supports XY. Keep a synthetic parent entry because
    // the child x/y entries alone lose that capability marker.
    if (item.type === 'composite' && item.name === 'color_xy') {
      result.push({
        name: 'color_xy',
        property: String(item.property || 'color_xy'),
        type: 'composite',
        access: typeof item.access === 'number' ? item.access : 3,
        unit: '',
        endpoint: endpointName !== undefined && endpointName !== null ? String(endpointName) : '',
        values: undefined,
        value_on: undefined,
        value_off: undefined
      });
    }
    const prop = item.property || item.name;
    if (prop) {
      result.push({
        name: String(item.name || prop),
        property: String(prop),
        type: String(item.type || 'numeric'),
        access: typeof item.access === 'number' ? item.access : 3,
        unit: item.unit ? String(item.unit) : '',
        endpoint: endpointName !== undefined && endpointName !== null ? String(endpointName) : '',
        values: Array.isArray(item.values) ? item.values.map(String) : undefined,
        value_on: item.value_on !== undefined ? String(item.value_on) : undefined,
        value_off: item.value_off !== undefined ? String(item.value_off) : undefined
      });
    }
  }
  list.forEach(item => walk(item, undefined));
  return result;
}

function stateExposes(exposes) {
  const seen = new Set();
  const result = [];
  for (const exp of exposes) {
    const prop = String(exp.property || '');
    if (exp.type !== 'binary' || !/^(state|switch)(_|$)/.test(prop)) continue;
    const key = `${prop}|${exp.endpoint !== undefined ? exp.endpoint : ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(exp);
  }
  return result;
}

// Extract Tuya DP definitions
function extractTuyaDatapoints(prep) {
  const dps = [];

  const exposes = parseExposes(prep.exposes);
  const endpoints = extractEndpoints(prep, exposes);
  const endpointForTarget = target => {
    const wanted = String(target || '');
    for (const exp of exposes) {
      if (String(exp.property || '') !== wanted) continue;
      const endpoint = resolveExplicitEndpoint(exp.endpoint, endpoints);
      if (endpoint > 0) return endpoint;
    }
    // A target suffix is only a physical endpoint when the official
    // endpoint map contains that exact name. Numeric logical suffixes
    // such as momentary_2 or week_program_3 must stay on the device's
    // default endpoint.
    const targetName = wanted.match(/_([^_]+)$/);
    if (targetName) {
      const named = resolveExplicitEndpoint(targetName[1], endpoints);
      if (named > 0) return named;
    }
    const ids = sortedEndpointIds(endpoints);
    return ids.length > 0 ? ids[0] : 1;
  };

  // A binary expose is authoritative for the wire encoding. Some upstream
  // definitions use a raw 0/1 converter for binary fields (for example
  // TRV26 window_detection), which would otherwise be sent as a 4-byte
  // Tuya value DP instead of the required 1-byte bool DP.
  const binaryProperties = new Set(
    parseExposes(prep.exposes)
      .filter(exp => String(exp.type || '').toLowerCase() === 'binary')
      .map(exp => String(exp.property || ''))
      .filter(Boolean)
  );

  // Official inbound path: tuya.datapoints.convert uses
  //   datapoints.find(d => d[0] === dpId)
  // so only the FIRST table row for a DP id ever decodes a report. A row
  // whose converter is composite (returns an object), async, or cannot be
  // probed at all cannot be reproduced by the declarative rule set. Those
  // rows must consume the report and publish nothing instead of guessing.
  const isAsyncConverter = fn =>
    !!fn && fn.constructor && fn.constructor.name === 'AsyncFunction';
  const classifyInboundConverter = conv => {
    if (!conv || typeof conv !== 'object') return 'no_converter';
    if (typeof conv.from !== 'function') return 'no_from';
    if (isAsyncConverter(conv.from)) return 'async_from';
    let sawAny = false;
    for (const probe of [true, 0, 1, 10, 100]) {
      let converted;
      try {
        converted = conv.from(probe, { device: {} }, {}, () => {}, {});
      } catch {
        continue;
      }
      if (converted === undefined || converted === null) continue;
      sawAny = true;
      if (typeof converted === 'object') return 'composite_from';
    }
    return sawAny ? null : 'unprobeable_from';
  };

  const inferDatatypeFromConverter = conv => {
    if (!conv || typeof conv !== 'object') return { datatype: 'value', scale: 1.0, offset: 0.0, map: null };
    const fromStr = String(conv.from || '');
    const toStr = String(conv.to || '');

    // Async converters can reject after the synchronous try/catch returns,
    // which would crash the whole extraction. Their payloads are also
    // device-specific, so skip them rather than guessing.
    const isAsync = fn => !!fn && fn.constructor && fn.constructor.name === 'AsyncFunction';
    if (isAsync(conv.from) || isAsync(conv.to)) {
      return { datatype: 'value', scale: 1.0, offset: 0.0, map: null };
    }

    const tryFrom = code => {
      try {
        return conv.from(code, { device: {} }, {});
      } catch {
        return undefined;
      }
    };

    if (typeof tryFrom(1) === 'boolean') return { datatype: 'bool', scale: 1.0, offset: 0.0, map: null };

    // Modern DP converters are fresh closures, so reference equality with
    // tuya.valueConverter.* never matches. Probe the pure converter to
    // recover numeric scaling and enum lookup tables.
    for (const probe of [10, 100, 2, 1000]) {
      const converted = tryFrom(probe);
      if (typeof converted === 'number' && Number.isFinite(converted) && converted !== probe) {
        return { datatype: 'value', scale: converted / probe, offset: 0.0, map: null };
      }
    }

    // to() is the reliable way to recover the wire datatype. A boolean
    // result means the DP is a Tuya bool (for example lockUnlock/onOff),
    // while an object carrying .value means it is an enum.
    const valueMap = {};
    let sawBooleanTo = false;
    if (typeof conv.to === 'function') {
      const candidates = new Set(['ON', 'OFF', 'LOCK', 'UNLOCK', 'off', 'heat', 'auto', 'cool']);
      for (let code = 0; code <= 32; code++) {
        const converted = tryFrom(code);
        if (typeof converted === 'string' && converted.length > 0) candidates.add(converted);
        else if (converted && typeof converted === 'object' && !Array.isArray(converted)) {
          for (const value of Object.values(converted)) {
            if (typeof value === 'string' && value.length > 0 && value !== 'none') candidates.add(value);
          }
        }
      }
      for (const label of candidates) {
        try {
          const converted = conv.to(label, { device: {} }, {});
          if (typeof converted === 'boolean') { sawBooleanTo = true; continue; }
          const numeric = Number(converted && typeof converted === 'object' && 'value' in converted ? converted.value : converted);
          if (Number.isFinite(numeric) && numeric >= 0 && numeric <= 255) valueMap[label] = numeric;
        } catch {}
      }
    }

    if (sawBooleanTo) return { datatype: 'bool', scale: 1.0, offset: 0.0, map: null };

    // Some converters (notably thermostatSystemModeAndPresetMap) return an
    // object from from() and expose their reverse mapping only through to().
    // Collect labels from both directions so those DPs keep enum semantics.
    for (let code = 0; code <= 32; code++) {
      const converted = tryFrom(code);
      if (typeof converted === 'string' && converted.length > 0) valueMap[converted] = code;
      else if (converted && typeof converted === 'object' && !Array.isArray(converted)) {
        for (const value of Object.values(converted)) {
          if (typeof value === 'string' && value.length > 0 && value !== 'none') valueMap[value] = code;
        }
      }
    }
    if (Object.keys(valueMap).length > 0) return { datatype: 'enum', scale: 1.0, offset: 0.0, map: valueMap };

    if (fromStr.includes('return !v') && toStr.includes('return !v')) {
      return { datatype: 'bool', scale: -1.0, offset: 1.0, map: null };
    }
    if (fromStr.includes('=== valueTrue') || fromStr.includes('=== valueTrue.valueOf()')) {
      return { datatype: 'bool', scale: 1.0, offset: 0.0, map: null };
    }

    let scale = 1.0;
    let m = fromStr.match(/v\s*\/\s*([0-9.]+)/) || toStr.match(/v\s*\*\s*([0-9.]+)/);
    if (m) {
      const divisor = Number(m[1]);
      if (divisor > 0) scale = 1.0 / divisor;
    } else {
      m = fromStr.match(/v\s*\*\s*([0-9.]+)/) || toStr.match(/v\s*\/\s*([0-9.]+)/);
      if (m && Number(m[1]) > 0) scale = Number(m[1]);
    }
    return { datatype: 'value', scale, offset: 0.0, map: null };
  };

  const legacyThermostatDps = [
    [legacyTuya?.dataPoints?.windowOpen ?? 115, 'window_open', 'bool', 1.0],
    [legacyTuya?.dataPoints?.childLock ?? 7, 'child_lock', 'bool', 1.0],
    [legacyTuya?.dataPoints?.heatingSetpoint ?? 2, 'current_heating_setpoint', 'value', 0.1],
    [legacyTuya?.dataPoints?.localTemp ?? 3, 'local_temperature', 'value', 0.1],
    [legacyTuya?.dataPoints?.battery ?? 21, 'battery', 'value', 1.0],
    [legacyTuya?.dataPoints?.mode ?? 4, 'system_mode', 'enum', 1.0]
  ];

  // Legacy Tuya thermostats keep their DP IDs in legacy.dataPoints and
  // decode them through tuya_thermostat, not a tuyaDatapoints table.
  const hasLegacyTuyaThermostat = Array.isArray(prep.fromZigbee) &&
    prep.fromZigbee.some(fz => String(fz && fz.convert || '').includes('firstDpValue(msg, meta, "tuya_thermostat")'));
  if (hasLegacyTuyaThermostat && (!prep.meta || !prep.meta.tuyaDatapoints)) {
    const legacyModeMap = {};
    if (prep.meta && prep.meta.tuyaThermostatSystemMode) {
      for (const [code, label] of Object.entries(prep.meta.tuyaThermostatSystemMode)) legacyModeMap[String(label)] = Number(code);
    }
    for (const [dp, target, datatype, scale] of legacyThermostatDps) {
      const map = target === 'system_mode' ? legacyModeMap : null;
      dps.push({ dp: Number(dp), target, datatype, scale, offset: 0.0, map });
    }
    for (const item of dps) item.endpoint = endpointForTarget(item.target);
    return dps;
  }

  // legacy.fz.tuya_switch predates meta.tuyaDatapoints. Its wire format is
  // nevertheless Tuya DP: DP1..DP6 are relay states and multiEndpoint maps
  // them to state_l1..state_l6 on one physical endpoint. Recover that table
  // from the exposes so these devices do not get a bogus genOnOff rule.
  const legacySwitchDps = extractLegacyTuyaSwitchDatapoints(prep);
  if (legacySwitchDps.length > 0) {
    // Moes wall switches combine tuya_switch with moes_switch for the
    // indicator and power-on settings. Those are enum DPs 15 and 14.
    const hasMoesSwitch = Array.isArray(prep.fromZigbee) && prep.fromZigbee.some(fz =>
      String(fz && fz.convert || '').includes('firstDpValue(msg, meta, "moes_switch")')
    );
    if (hasMoesSwitch) {
      const powerOnMap = {};
      for (const [code, label] of Object.entries(legacyTuya?.moesSwitch?.powerOnBehavior || {})) powerOnMap[String(label)] = Number(code);
      const indicateMap = {};
      for (const [code, label] of Object.entries(legacyTuya?.moesSwitch?.indicateLight || {})) indicateMap[String(label)] = Number(code);
      legacySwitchDps.push({ dp: Number(legacyTuya?.dataPoints?.moesSwitchPowerOnBehavior ?? 14), target: 'power_on_behavior', datatype: 'enum', scale: 1.0, offset: 0.0, map: powerOnMap });
      legacySwitchDps.push({ dp: Number(legacyTuya?.dataPoints?.moesSwitchIndicateLight ?? 15), target: 'indicate_light', datatype: 'enum', scale: 1.0, offset: 0.0, map: indicateMap });
    }
    for (const item of legacySwitchDps) item.endpoint = endpointForTarget(item.target);
    return legacySwitchDps;
  }

  if (!prep.meta || !prep.meta.tuyaDatapoints) return dps;
  const meta = prep.meta;
  const tuyaSendCommand = meta.tuyaSendCommand === 'sendData' ? 0x04 : 0x00;

  const firstDpRow = new Set();
  for (const item of meta.tuyaDatapoints) {
    if (!Array.isArray(item) || item.length < 2) continue;
    const dpId = item[0];
    const prop = item[1];
    if (!prop) continue;

    // Official find() semantics: only the first row per DP id owns the
    // inbound decode. Later rows are still usable for toZigbee (the official
    // set converter searches by property name) but must never decode a
    // report.
    const alreadySeenDp = firstDpRow.has(Number(dpId));
    firstDpRow.add(Number(dpId));

    // Official find() ignores the property name when locating the row: the
    // very first row for a DP id always wins, even when its property is
    // null. A null property means the converter returns an object that is
    // merged into the published state, which the declarative rule set
    // cannot reproduce. Such a row must consume the report.
    const inboundReason = alreadySeenDp
      ? 'duplicate_dp_row_not_first'
      : (!prop ? 'composite_property_merge' : classifyInboundConverter(item[2]));

    if (!prop) {
      inboundAudit.push({
        model: String(prep.model || ''),
        vendor: String(prep.vendor || ''),
        dp: Number(dpId),
        property: '',
        reason: inboundReason,
        source: String(item[2] && item[2].from || '').slice(0, 200)
      });
      continue;
    }

    let { datatype, scale, offset, map } = inferDatatypeFromConverter(item[2]);

    if (prop === 'system_mode' && meta.tuyaThermostatSystemMode) {
      datatype = 'enum';
      map = {};
      for (const [code, label] of Object.entries(meta.tuyaThermostatSystemMode)) map[String(label)] = Number(code);
    } else if (prop === 'preset' && meta.tuyaThermostatPreset) {
      datatype = 'enum';
      map = {};
      for (const [code, label] of Object.entries(meta.tuyaThermostatPreset)) map[String(label)] = Number(code);
    }

    // Some DPs are declared as raw but exposed as binary switches.
    // Keep the 1-byte bool wire encoding instead of sending a 32-bit value.
    if (binaryProperties.has(String(prop)) && datatype === 'value') {
      datatype = 'bool';
      scale = 1.0;
      offset = 0.0;
      map = null;
    }

    const rawTarget = String(prop);
    const stateMatch = rawTarget.match(/^(?:state|switch)_?(?:l)?([1-9][0-9]*)$/i);
    const target = stateMatch ? `state_l${stateMatch[1]}` : rawTarget;
    dps.push({ dp: Number(dpId), target, datatype, scale, offset, map, sendCommand: tuyaSendCommand });
    dps[dps.length - 1].endpoint = endpointForTarget(target);
    if (inboundReason) {
      dps[dps.length - 1].inboundUnsupported = true;
      dps[dps.length - 1].inboundReason = inboundReason;
      inboundAudit.push({
        model: String(prep.model || ''),
        vendor: String(prep.vendor || ''),
        dp: Number(dpId),
        property: String(prop),
        reason: inboundReason,
        source: String(item[2] && item[2].from || '').slice(0, 200)
      });
    }
  }
  return dps;
}

// Extract the named endpoint map without collapsing multi-endpoint devices.
// deviceEndpoints() already owns an explicit map; exposes carry the same
// endpoint names for custom definitions. The dummy-device probe is kept
// only as a last-resort fallback because it cannot know real endpoint IDs.
function extractEndpoints(prep, exposes) {
  const epMap = {};
  const addNumeric = source => {
    if (!source || typeof source !== 'object') return;
    for (const [key, value] of Object.entries(source)) {
      if (typeof value === 'number' && value > 0) epMap[String(key)] = value;
    }
  };

  addNumeric(prep.endpoint);
  if (typeof prep.endpoint === 'function') {
    try {
      const probeIds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
      const dummyDevice = {
        endpoints: probeIds.map(ID => ({ ID, inputClusters: [6, 8, 0x0300], outputClusters: [] })),
        getEndpoint: id => ({ ID: id, inputClusters: [6, 8, 0x0300], outputClusters: [] })
      };
      addNumeric(prep.endpoint(dummyDevice));
    } catch {}
  }

  // exposeEndpoints() names the physical endpoint used by each expose.
  // It is the most reliable source for devices whose endpoint() callback
  // depends on a fully interviewed device object.
  const namedIds = new Set(Object.keys(epMap));
  for (const exp of Array.isArray(exposes) ? exposes : []) {
    const name = exp && exp.endpoint !== undefined && exp.endpoint !== null ? String(exp.endpoint) : '';
    if (!name || namedIds.has(name)) continue;
    const numeric = /^[0-9]+$/.test(name) ? Number(name) : NaN;
    if (Number.isFinite(numeric) && numeric > 0) {
      epMap[name] = numeric;
      namedIds.add(name);
      continue;
    }
    // Named endpoints are conventionally numbered in declaration order.
    // This also gives a stable route when the upstream callback needs a
    // fully interviewed device to recover its real IDs.
    const nextId = Math.max(0, ...Object.values(epMap)) + 1;
    epMap[name] = nextId;
    namedIds.add(name);
  }

  if (Object.keys(epMap).length === 0) epMap.default = 1;

  // Runtime gang numbering follows this serialized order. Keep endpoint
  // IDs ascending so declaration order cannot redirect state_lN.
  const ordered = {};
  for (const [name, id] of sortedEndpointEntries(epMap)) ordered[name] = id;
  for (const key of Object.keys(epMap)) delete epMap[key];
  Object.assign(epMap, ordered);
  return epMap;
}


// Convert fromZigbee list to IR v5 rules
// Endpoint capability bits are serialized in EndpointDesc.pad8. They let
// HomeKit expose only the functions the official definition gives to that
// physical endpoint. This matters for RGBW controllers whose endpoints are
// not contiguous (for example GL-C-008-2ID uses endpoints 11 and 15).
const ENDPOINT_CAP_STATE = 0x01;
const ENDPOINT_CAP_BRIGHTNESS = 0x02;
const ENDPOINT_CAP_COLOR_TEMP = 0x04;
const ENDPOINT_CAP_COLOR_XY = 0x08;
const ENDPOINT_CAP_COVER = 0x10;
const ENDPOINT_CAP_THERMOSTAT = 0x20;
const ENDPOINT_CAP_SENSOR = 0x40;

function deriveEndpointCapabilities(prep, endpoints, exposes, fromRules, toRules, tuyaDps) {
  const result = {};
  const mark = (endpoint, flags) => {
    const id = Number(endpoint || 0);
    if (!id) return;
    result[id] = (result[id] || 0) | flags;
  };
  const markRule = rule => {
    const endpoint = Number(rule && rule.endpoint || 0);
    if (!endpoint) return;
    const cluster = parseInt(String(rule.cluster || '0'), 16);
    const target = String(rule.target || rule.exposeField || '');
    const command = Number(rule.cmd !== undefined ? rule.cmd : 0);
    const attribute = Number(rule.attr !== undefined ? rule.attr : 0);
    const isColorTemp = target === 'color_temp' || target.startsWith('color_temp_') ||
      target.startsWith('color_temp_startup');
    const isColorXY = target === 'color' || target === 'color_xy' || target.startsWith('color_xy_') ||
      /(?:^|_)(?:x|y|hue|saturation)(?:_|$)/.test(target);
    if (cluster === 0x0006 || /^state(?:_l[1-9][0-9]*)?$/.test(target)) mark(endpoint, ENDPOINT_CAP_STATE);
    if (cluster === 0x0008 || target.startsWith('brightness')) mark(endpoint, ENDPOINT_CAP_BRIGHTNESS);
    // Command opcodes and attribute IDs can have the same numeric value
    // (0x0007 is color temperature, while 0x07 is moveToColor). Classify
    // by the official target first, then by the operation-specific number.
    if (cluster === 0x0300 && (isColorTemp || attribute === 0x0007 ||
        (command === 0x0A && !isColorXY))) {
      mark(endpoint, ENDPOINT_CAP_COLOR_TEMP);
    }
    if (cluster === 0x0300 && (isColorXY || command === 0x07 ||
        command === 0x03 || command === 0x04)) {
      mark(endpoint, ENDPOINT_CAP_COLOR_XY);
    }
    if (cluster === 0x0102 || target.startsWith('position') || target.startsWith('tilt')) mark(endpoint, ENDPOINT_CAP_COVER);
    if (cluster === 0x0201 || /^(?:local_temperature|occupied_heating_setpoint|current_heating_setpoint|system_mode)/.test(target)) mark(endpoint, ENDPOINT_CAP_THERMOSTAT);
    if ([0x0001, 0x0400, 0x0402, 0x0405, 0x0406, 0x040D, 0x0500, 0x0702, 0x0B04].includes(cluster)) mark(endpoint, ENDPOINT_CAP_SENSOR);
  };

  for (const rule of [...fromRules, ...toRules]) markRule(rule);
  for (const dp of tuyaDps) markRule({cluster: 0xEF00, target: dp.target, endpoint: dp.endpoint});

  for (const exp of exposes) {
    const route = routePropertyForExpose(exp, endpoints, prep.meta);
    const endpoint = route.endpoint || (sortedEndpointIds(endpoints).length === 1 ? sortedEndpointIds(endpoints)[0] : 0);
    if (!endpoint) continue;
    const property = String(route.property || '');
    if (/^(?:state|switch)(?:_|$)/.test(property)) mark(endpoint, ENDPOINT_CAP_STATE);
    if (property.startsWith('brightness')) mark(endpoint, ENDPOINT_CAP_BRIGHTNESS);
    if (property.startsWith('color_temp')) mark(endpoint, ENDPOINT_CAP_COLOR_TEMP);
    if (property === 'color' || property === 'color_xy' || property === 'hue' ||
        property === 'saturation' || property === 'x' || property === 'y' ||
        property.startsWith('color_xy_')) {
      mark(endpoint, ENDPOINT_CAP_COLOR_XY);
    }
    if (/^(?:position|tilt)(?:_|$)/.test(property)) mark(endpoint, ENDPOINT_CAP_COVER);
    if (/^(?:local_temperature|occupied_heating_setpoint|current_heating_setpoint|system_mode)(?:_|$)/.test(property)) mark(endpoint, ENDPOINT_CAP_THERMOSTAT);
    if (/^(?:temperature|humidity|battery|voltage|illuminance|occupancy|contact|water_leak|smoke|gas|carbon_monoxide|vibration)(?:_|$)/.test(property)) mark(endpoint, ENDPOINT_CAP_SENSOR);
  }

  const named = {};
  for (const [name, id] of Object.entries(endpoints)) {
    const endpoint = Number(id);
    if (endpoint > 0) named[String(name)] = result[endpoint] || 0;
  }
  return { byEndpoint: result, named };
}
// Official command converters are event sources, not attribute reporters.
// Emit only semantics that can be reproduced without timers/globalStore.
function generateCommandEventIR(prep, clusterIds, endpoints) {
  // These are the only command converters the IR VM can execute with
  // official-equivalent semantics. Everything else is surfaced through
  // the coverage audit instead of silently pretending to be supported.
  const rules = [];
  const added = new Set();
  // 0 means "any physical endpoint". ZHC applies postfixWithEndpointName
  // to the actual message endpoint; a fixed probe endpoint would make
  // multi-endpoint remotes miss every event outside that one endpoint.
  const probeEndpointIds = [0];

  const commandSpecs = new Map([
    [zhc.fromZigbee.command_store, {kind: 'literal', value: 'store', field: 'sceneid', action: true}],
    [zhc.fromZigbee.command_recall, {kind: 'literal', value: 'recall', field: 'sceneid', action: true}],
    [zhc.fromZigbee.command_panic, {kind: 'literal', value: 'panic', action: true}],
    [zhc.fromZigbee.command_emergency, {kind: 'literal', value: 'emergency', action: true}],
    [zhc.fromZigbee.command_arm, {kind: 'arm', action: true}],
    [zhc.fromZigbee.command_arm_with_transaction, {kind: 'arm', action: true, limited: true}],
    [zhc.fromZigbee.command_cover_stop, {kind: 'literal', value: 'stop', action: true}],
    [zhc.fromZigbee.command_cover_open, {kind: 'literal', value: 'open', action: true}],
    [zhc.fromZigbee.command_cover_close, {kind: 'literal', value: 'close', action: true}],
    [zhc.fromZigbee.command_on, {kind: 'literal', value: 'on', action: true}],
    [zhc.fromZigbee.command_off, {kind: 'literal', value: 'off', action: true}],
    [zhc.fromZigbee.command_off_with_effect, {kind: 'literal', value: 'off', action: true}],
    [zhc.fromZigbee.command_toggle, {kind: 'literal', value: 'toggle', action: true}],
    [zhc.fromZigbee.command_move_to_level, {kind: 'move_to_level', action: true}],
    [zhc.fromZigbee.command_move, {kind: 'move', action: true}],
    [zhc.fromZigbee.command_step, {kind: 'step', action: true}],
    [zhc.fromZigbee.command_stop, {kind: 'literal', value: 'brightness_stop', action: true}],
    [zhc.fromZigbee.command_move_color_temperature, {kind: 'color_temp_move', action: true}],
    [zhc.fromZigbee.command_stop_move_step, {kind: 'literal', value: 'stop_move_step', action: true}],
    [zhc.fromZigbee.command_step_color_temperature, {kind: 'color_temp_step', action: true}],
    [zhc.fromZigbee.command_enhanced_move_to_hue_and_saturation, {kind: 'enhanced_hue_sat', action: true}],
    [zhc.fromZigbee.command_move_to_hue_and_saturation, {kind: 'hue_sat', action: true}],
    [zhc.fromZigbee.command_step_hue, {kind: 'hue_step', action: true}],
    [zhc.fromZigbee.command_step_saturation, {kind: 'saturation_step', action: true}],
    [zhc.fromZigbee.command_color_loop_set, {kind: 'color_loop', action: true}],
    [zhc.fromZigbee.command_move_to_color_temp, {kind: 'color_temp', action: true}],
    [zhc.fromZigbee.command_move_to_color, {kind: 'color_xy', action: true}],
    [zhc.fromZigbee.command_move_hue, {kind: 'hue_move', action: true}],
    [zhc.fromZigbee.command_move_to_saturation, {kind: 'saturation', action: true}],
    [zhc.fromZigbee.command_move_to_hue, {kind: 'hue', action: true}],
    [zhc.fromZigbee.command_on_state, {kind: 'state_on'}],
    [zhc.fromZigbee.command_off_state, {kind: 'state_off'}],
    [zhc.fromZigbee.ewelink_action, {kind: 'ewelink'}],
    [zhc.fromZigbee.command_status_change_notification_action, {kind: 'ias_action'}],
    [zhc.fromZigbee.ignore_command_on, {kind: 'ignore'}],
    [zhc.fromZigbee.ignore_command_off, {kind: 'ignore'}],
    [zhc.fromZigbee.ignore_command_off_with_effect, {kind: 'ignore'}],
    [zhc.fromZigbee.ignore_command_step, {kind: 'ignore'}],
    [zhc.fromZigbee.ignore_command_stop, {kind: 'ignore'}],
    [zhc.fromZigbee.ignore_iaszone_statuschange, {kind: 'ignore'}],
  ]);

  const converters = Array.isArray(prep.fromZigbee) ? prep.fromZigbee : [];
  for (const fz of converters) {
    let spec = commandSpecs.get(fz);
    if (!spec) {
      for (const [reference, candidate] of commandSpecs) {
        if (reference && fz && reference.convert === fz.convert) { spec = candidate; break; }
      }
    }
    if (!spec) continue;
    const types = Array.isArray(fz.type) ? fz.type : [fz.type];
    const clusters = Array.isArray(fz.cluster) ? fz.cluster : [fz.cluster];
    for (const clusterName of clusters) {
      const cluster = resolveClusterId(clusterName);
      if (!cluster) continue;
      clusterIds.add(cluster);
      for (const type of types) {
        if (!String(type).startsWith('command')) continue;
        const command = officialCommandId(clusterName, type);
        if (command === undefined) continue;
        for (const endpointId of probeEndpointIds) {
          const target = spec.action ? 'action' : 'state';
          const key = `${cluster}:${command}:${endpointId}:${spec.kind}:${target}`;
          if (added.has(key)) continue;
          added.add(key);
          rules.push({
            op: 'COMMAND_EVENT',
            kind: spec.kind,
            value: spec.value || '',
            // Payload field name for composite events. The runtime maps
            // it to the official published property itself.
            field: spec.field || '',
            cluster: hex16(cluster),
            cmd: hex16(command),
            endpoint: endpointId,
            target,
            limited: spec.limited === true,
            scale: 1.0,
            offset: 0.0,
          });
        }
      }
    }
  }
  return rules;
}

function generateFromZigbeeIR(prep, clusterIds, endpoints, exposes) {
  const rules = [];
  const addedKeys = new Set();

  function addRule(rule) {
    const key = `${rule.cluster}:${rule.attr}:${rule.target}:${rule.endpoint || 0}`;
    if (!addedKeys.has(key)) {
      addedKeys.add(key);
      rules.push(rule);
    }
  }

  // Official ignore_* converters consume a matching report and publish
  // nothing. Serialize that semantic explicitly so the runtime fallback
  // cannot invent state which ZHC intentionally suppresses.
  const ignoredClusters = new Set();
  for (const fz of (Array.isArray(prep.fromZigbee) ? prep.fromZigbee : [])) {
    const source = String(fz && fz.convert || '').replace(/\s+/g, '');
    if (!/^(?:async)?\([^)]*\)=>\{\}$/.test(source)) continue;
    const clusters = Array.isArray(fz.cluster) ? fz.cluster : [fz.cluster];
    for (const clName of clusters) {
      const clId = resolveClusterId(clName);
      if (clId) ignoredClusters.add(clId);
    }
  }
  for (const clId of ignoredClusters) {
    clusterIds.add(clId);
    addRule({
      op: 'IGNORE',
      cluster: hex16(clId),
      attr: '0xFFFF',
      datatype: 'uint8',
      endpoint: 0,
      scale: 1.0,
      offset: 0.0,
      target: ''
    });
  }

  // On/Off exposes are the source of truth for gang count and endpoint.
  // Tuya virtual gangs reuse one physical endpoint through DPs, so the DP
  // rule below wins and a duplicate ZCL rule must not be emitted.
  const stateItems = stateExposes(exposes);
  // Follow the official genOnOff converter output instead of assuming that
  // every definition referencing genOnOff is a relay. Many remotes use the
  // same cluster for commandOn/commandOff and publish action, not state.
  const onOffInspection = officialOnOffInspection(prep, endpoints);
  for (const unsupported of onOffInspection.unsupported) {
    inboundAudit.push({
      model: String(prep.model || ''),
      vendor: String(prep.vendor || ''),
      dp: 0,
      property: String(unsupported.property || ''),
      reason: unsupported.reason,
      source: unsupported.source,
    });
  }
  const semanticLimited = onOffInspection.unsupported.length > 0;
  const tuyaStateDps = extractTuyaDatapoints(prep).filter(
    dp => /^state_l[1-9][0-9]*$/.test(String(dp.target || ''))
  );
  // Include plain state for legacy one-gang Tuya switches. Their wire
  // encoding is still 0xEF00 even though the expose is named state.
  const tuyaSwitchDps = extractTuyaDatapoints(prep).filter(dp => {
    const target = String(dp.target || '');
    return /^state_l[1-9][0-9]*$/.test(target) || target === 'state';
  });
  const tuyaStateTargets = new Set(tuyaSwitchDps.map(dp => String(dp.target)));
  // Every Tuya DP target is already represented in the unpacked
  // tuyaDps table with its wire type and enum map. Generating a second
  // generic "value" rule here can shadow the richer rule at runtime.
  const tuyaAllTargets = new Set(extractTuyaDatapoints(prep).map(dp => String(dp.target || '')));
  // Every DP target is represented in the richer tuyaDatapoints table.
  // A second generic READ_ATTRIBUTE entry would be emitted first and shadow
  // its wire type / enum map (for example Tuya cover OPEN/STOP/CLOSE).
  const isDoorLock = hasLockExposeSemantics(exposes);
  const hasStandardLockState = isDoorLock && hasStandardDoorLockStateConverter(prep);
  const iasPropertySet = new Set(
    exposes.map(exp => String(exp && exp.property || '').toLowerCase()).filter(Boolean)
  );
  const iasHas = (...names) => names.some(name => iasPropertySet.has(name));

  // IAS status conversion is defined by the converter function, not by
  // the exposed property name. In particular ias_no_alarm only publishes
  // tamper/battery_low and must never synthesize a contact state.
  const iasRuleTargets = new Map();
  const addIasRule = (target, bit, invert = false) => {
    if (!iasRuleTargets.has(target)) iasRuleTargets.set(target, {bit, invert});
  };
  const iasConverters = Array.isArray(prep.fromZigbee) ? prep.fromZigbee : [];
  const sameConverter = (candidate, reference) => candidate === reference ||
    (candidate && reference && candidate.convert === reference.convert);
  const iasHasConverter = reference => iasConverters.some(fz => sameConverter(fz, reference));
  const isIasZoneConverter = fz => {
    const clusters = Array.isArray(fz && fz.cluster) ? fz.cluster : [fz && fz.cluster];
    return clusters.some(cluster => resolveClusterId(cluster) === 0x0500);
  };
  const observeIasConverter = fz => {
    if (!fz || typeof fz.convert !== 'function' || !isIasZoneConverter(fz)) return null;
    const observed = {};
    const probe = (zoneStatus, bit = null) => {
      const msg = {
        type: 'attributeReport',
        data: {zoneStatus, zonestatus: zoneStatus},
        endpoint: {},
      };
      let published = null;
      try {
        published = fz.convert({meta: {}}, msg, value => { published = value; }, {}, {});
      } catch (err) {
        // Some vendor converters claim ssIasZone but require the full
        // Tuya message envelope. A failed synthetic probe must never
        // abort extraction of the remaining definitions.
        if (err) return;
        return;
      }
      if (published && typeof published === 'object') {
        for (const [key, value] of Object.entries(published)) {
          if (typeof value !== 'boolean') continue;
          const target = String(key);
          if (!observed[target]) observed[target] = {};
          observed[target][bit === null ? 'baseline' : `bit${bit}`] = value;
        }
      }
    };
    probe(0);
    for (let bit = 0; bit <= 3; bit++) probe(1 << bit, bit);
    return observed;
  };
  const iasSemantics = {};
  for (const fz of iasConverters) {
    const observed = observeIasConverter(fz);
    if (!observed) continue;
    for (const [target, values] of Object.entries(observed)) {
      const baseline = values.baseline;
      if (typeof baseline !== 'boolean') continue;
      const samples = Object.entries(values)
        .filter(([key, value]) => /^bit[0-3]$/.test(key) && typeof value === 'boolean')
        .map(([key, value]) => ({bit: Number(key.slice(3)), value}))
        .filter(sample => sample.value !== baseline);
      if (samples.length !== 1) continue;
      const control = samples[0];
      iasSemantics[target] = {bit: control.bit, invert: control.value === false};
    }
  }
  const iasOnlyNoAlarm = iasHasConverter(zhc.fromZigbee.ias_no_alarm) &&
    !iasConverters.some(fz => !sameConverter(fz, zhc.fromZigbee.ias_no_alarm) &&
      resolveClusterId(Array.isArray(fz && fz.cluster) ? fz.cluster[0] : fz && fz.cluster) === 0x0500);

  for (const [target, semantics] of Object.entries(iasSemantics)) {
    addIasRule(target, semantics.bit, semantics.invert);
  }

  if (iasRuleTargets.size === 0 && !iasOnlyNoAlarm) {
    if (iasHas('water_leak', 'waterleak', 'water_leak_alarm_1')) addIasRule('water_leak', 0);
    else if (iasHas('smoke', 'smoke_alarm_1')) addIasRule('smoke', 0);
    else if (iasHas('gas_leak', 'gas', 'gas_alarm_1')) addIasRule('gas', 0);
    else if (iasHas('gas_alarm_2')) addIasRule('gas', 1);
    else if (iasHas('carbon_monoxide', 'carbon_monoxide_alarm_1')) addIasRule('carbon_monoxide', 0);
    else if (iasHas('occupancy', 'presence', 'motion', 'occupancy_alarm_1')) addIasRule('occupancy', 0);
    else if (iasHas('occupancy_alarm_2')) addIasRule('occupancy', 1);
    else if (iasHas('vibration', 'vibration_alarm_1')) addIasRule('vibration', 0);
    else if (iasHas('sos', 'sos_alarm_2')) addIasRule('alarm', 1);
    else if (iasHas('contact')) addIasRule('contact', 0);
    else if (iasHas('alarm', 'alarm_1')) addIasRule('alarm', 0);
  }
  const iasRuleList = Array.from(iasRuleTargets, ([target, semantics]) => ({
    target,
    bit: semantics.bit,
    invert: semantics.invert === true,
  }));
  if (!isDoorLock) {
    // The official converter result is authoritative. A genOnOff
    // attribute converter that returns only action, cover state, or no
    // state must never be materialized as a synthetic relay.
    for (const [target, inspectedEndpoint] of onOffInspection.targets) {
      if (tuyaStateTargets.has(target)) continue;
      if (tuyaAllTargets.has(target)) continue;
      const matchingExpose = stateItems.find(exp =>
        canonicalStateExpose(exp, endpoints).property === target);
      const normalized = matchingExpose
        ? canonicalStateExpose(matchingExpose, endpoints)
        : canonicalStateProperty(target, endpoints);
      const endpoint = normalized.property === 'state'
        ? 0
        : (normalized.endpoint || inspectedEndpoint || 0);
      addRule({
        op: 'READ_ATTRIBUTE',
        cluster: hex16(0x0006),
        attr: hex16(0x0000),
        datatype: 'bool',
        endpoint,
        scale: 1.0,
        offset: 0.0,
        target: normalized.property
      });
      clusterIds.add(0x0006);
    }
    // The converter probe uses one synthetic endpoint. For multi-endpoint
    // devices, official exposes already contain one route per gang, so
    // materialize any route the probe could not synthesize. This keeps
    // the official expose order and endpoint binding for all brands.
    if (onOffInspection.targets.size > 0) {
      for (const exp of stateItems) {
        const route = canonicalStateExpose(exp, endpoints);
        if (!route.property || (route.property !== 'state' &&
            !/^state_l[1-9][0-9]*$/.test(route.property))) continue;
        if (tuyaStateTargets.has(route.property) || tuyaAllTargets.has(route.property)) continue;
        addRule({
          op: 'READ_ATTRIBUTE',
          cluster: hex16(0x0006),
          attr: hex16(0x0000),
          datatype: 'bool',
          endpoint: route.property === 'state' ? 0 : route.endpoint,
          scale: 1.0,
          offset: 0.0,
          target: route.property
        });
        clusterIds.add(0x0006);
      }
    }
  } else if (hasStandardLockState) {
    // Standard locks report lockState (0x0000) on the Door Lock cluster.
    // Do not synthesize a genOnOff report: it is a different cluster and
    // would overwrite the real lock state on devices that also expose one.
    const endpoint = stateItems.length > 0 ? canonicalStateExpose(stateItems[0], endpoints).endpoint : 0;
    addRule({
      op: 'READ_ATTRIBUTE',
      cluster: hex16(0x0101),
      attr: hex16(0x0000),
      datatype: 'uint8',
      endpoint,
      scale: 1.0,
      offset: 0.0,
      target: 'lock_state'
    });
    clusterIds.add(0x0101);
  }

  // One Tuya DP rule per virtual gang. The DP id is the physical control
  // address; state_lN is only the logical UI/HomeKit name.
  for (const dp of tuyaStateDps) {
    const match = String(dp.target).match(/^state_l([1-9][0-9]*)$/);
    if (!match) continue;
    if (tuyaAllTargets.has(String(dp.target))) continue;
    addRule({
      op: 'READ_ATTRIBUTE',
      cluster: hex16(0xEF00),
      attr: hex16(Number(dp.dp)),
      datatype: dp.datatype === 'bool' ? 'bool' : 'value',
      endpoint: 1,
      scale: dp.scale,
      offset: dp.offset,
      target: `state_l${match[1]}`
    });
    clusterIds.add(0xEF00);
  }
  for (const dp of tuyaSwitchDps) {
    if (String(dp.target) !== 'state') continue;
    if (tuyaAllTargets.has('state')) continue;
    addRule({
      op: 'READ_ATTRIBUTE',
      cluster: hex16(0xEF00),
      attr: hex16(Number(dp.dp)),
      datatype: dp.datatype === 'bool' ? 'bool' : 'value',
      endpoint: 1,
      scale: dp.scale,
      offset: dp.offset,
      target: 'state'
    });
    clusterIds.add(0xEF00);
  }
  // Iterate over prep.fromZigbee for non-state clusters.
  if (Array.isArray(prep.fromZigbee)) {
    for (const fz of prep.fromZigbee) {
      if (!fz) continue;
      const clusters = Array.isArray(fz.cluster) ? fz.cluster : [fz.cluster];
      for (const clName of clusters) {
        const clId = resolveClusterId(clName);
        if (!clId) continue;
        clusterIds.add(clId);

        // Standard ZCL Cluster Mapping
        if (clId === 0x0006) { // OnOff
          // The official onOff inspection above is the only source of
          // attribute state rules. Command-only and action-only
          // definitions intentionally leave this block empty.
        } else if (clId === 0x0008) { // LevelControl
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0008), attr: hex16(0x0000), datatype: 'uint8', scale: 1.0, offset: 0.0, target: 'brightness' });
        } else if (clId === 0x0300) { // ColorControl
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0300), attr: hex16(0x0007), datatype: 'uint16', scale: 1.0, offset: 0.0, target: 'color_temp' });
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0300), attr: hex16(0x0003), datatype: 'uint16', scale: 1.0, offset: 0.0, target: 'color_x' });
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0300), attr: hex16(0x0004), datatype: 'uint16', scale: 1.0, offset: 0.0, target: 'color_y' });
        } else if (clId === 0x0402) { // Temperature
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0402), attr: hex16(0x0000), datatype: 'int16', scale: 0.01, offset: 0.0, target: 'temperature' });
        } else if (clId === 0x0405) { // Humidity
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0405), attr: hex16(0x0000), datatype: 'uint16', scale: 0.01, offset: 0.0, target: 'humidity' });
        } else if (clId === 0x0406) { // Occupancy
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0406), attr: hex16(0x0000), datatype: 'uint8', scale: 1.0, offset: 0.0, target: 'occupancy' });
        } else if (clId === 0x0400) { // Illuminance
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0400), attr: hex16(0x0000), datatype: 'uint16', scale: 1.0, offset: 0.0, target: 'illuminance' });
        } else if (clId === 0x0500) { // IAS Zone
          // One ZHC converter can publish several bits from the same
          // zoneStatus word (for example CO Alarm 1 + Gas Alarm 2).
          // Emit one rule per semantic property and decode each bit
          // independently at runtime.
          for (const iasRule of iasRuleList) {
            addRule({
              op: 'READ_ATTRIBUTE',
              cluster: hex16(0x0500),
              attr: hex16(0x0002),
              datatype: 'uint16',
              scale: 1.0,
              offset: 0.0,
              target: iasRule.target,
              iasBit: iasRule.bit,
              iasInvert: iasRule.invert,
            });
          }
        } else if (clId === 0x0001) { // PowerCfg
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0001), attr: hex16(0x0021), datatype: 'uint8', scale: 0.5, offset: 0.0, target: 'battery' });
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0001), attr: hex16(0x0020), datatype: 'uint8', scale: 0.1, offset: 0.0, target: 'voltage' });
        } else if (clId === 0x0B04) { // Electrical Measurement
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0B04), attr: hex16(0x050B), datatype: 'int16', scale: 1.0, offset: 0.0, target: 'power' });
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0B04), attr: hex16(0x0505), datatype: 'uint16', scale: 1.0, offset: 0.0, target: 'voltage' });
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0B04), attr: hex16(0x0508), datatype: 'uint16', scale: 0.001, offset: 0.0, target: 'current' });
        } else if (clId === 0x0702) { // Metering
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0702), attr: hex16(0x0000), datatype: 'uint48', scale: 0.001, offset: 0.0, target: 'energy' });
        } else if (clId === 0x0101) { // Door Lock
          // Only a converter that decodes the standard lockState attribute
          // can use the standard Door Lock path. Aqara converters use this
          // cluster as a container for proprietary keys.
          if (hasStandardLockState) {
            addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0101), attr: hex16(0x0000), datatype: 'uint8', scale: 1.0, offset: 0.0, target: 'lock_state' });
          }
        } else if (clId === 0x0102) { // Window Covering
          addRule({
            op: 'READ_ATTRIBUTE',
            cluster: hex16(0x0102),
            attr: hex16(0x0008),
            datatype: 'uint8',
            scale: 1.0,
            offset: 0.0,
            target: 'position',
            coverInverted: prep.meta && prep.meta.coverInverted === true,
          });
        } else if (clId === 0x0201) { // Thermostat
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0201), attr: hex16(0x0000), datatype: 'int16', scale: 0.01, offset: 0.0, target: 'local_temperature' });
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0201), attr: hex16(0x0012), datatype: 'int16', scale: 0.01, offset: 0.0, target: 'occupied_heating_setpoint' });
          addRule({ op: 'READ_ATTRIBUTE', cluster: hex16(0x0201), attr: hex16(0x001C), datatype: 'enum8', scale: 1.0, offset: 0.0, target: 'system_mode' });
        }
      }
    }
  }

  return rules;
}

// Convert the official toZigbee table to IR rules. Each official converter
// entry owns its endpoints; flattening keys first loses which endpoint a
// state/brightness/color command belongs to.
function generateToZigbeeIR(prep, clusterIds, endpoints, exposes) {
  const rules = [];
  const addedKeys = new Set();
  const stateItems = stateExposes(exposes);
  const isDoorLock = hasLockExposeSemantics(exposes);
  const tuyaStateTargets = new Set(
    extractTuyaDatapoints(prep)
      .map(dp => String(dp.target || ''))
      .filter(target => /^state_l[1-9][0-9]*$/.test(target) || target === 'state')
  );

  function addRule(rule) {
    const key = `${rule.cluster}:${rule.target}:${rule.endpoint || 0}:${rule.op}:${rule.cmd || rule.attr || 0}`;
    if (addedKeys.has(key)) return;
    addedKeys.add(key);
    rules.push(rule);
  }

  function exposeRoutesForBase(base, stateOnly = false) {
    const routes = [];
    const seen = new Set();
    const candidates = stateOnly ? stateItems : exposes;
    for (const exp of candidates) {
      const raw = String(exp && exp.property || '');
      const matches = stateOnly
        ? /^(?:state|switch)(?:_|$)/i.test(raw)
        : propertyMatchesExpose(raw, base, endpoints);
      if (!matches) continue;
      const route = stateOnly
        ? canonicalStateExpose(exp, endpoints)
        : routePropertyForExpose(exp, endpoints, prep.meta);
      if (!route.property) continue;
      if (stateOnly && route.endpoint === 0 && stateItems.some(other =>
          other !== exp && canonicalStateExpose(other, endpoints).endpoint > 0)) continue;
      const key = `${route.property}:${route.endpoint}`;
      if (seen.has(key)) continue;
      seen.add(key);
      routes.push(route);
    }
    return routes;
  }

  // Official expose names such as brightness_rgb, brightness_white or
  // color_temp_cct already identify the physical endpoint. HomeKit and the
  // generic action API address those outputs by gang, so add a canonical
  // brightness_lN / color_temp_lN alias. Keep the official field as well:
  // Z2M semantics and the original property must remain available.
  function addGangAliases(officialRules, exposes, endpoints, meta) {
    const aliases = new Map();
    const addAlias = (base, officialRule) => {
      const endpoint = Number(officialRule.endpoint || 0);
      if (!endpoint) return;
      const gang = statePropertyForEndpoint(endpoints, endpoint);
      const match = gang.match(/^state_l([1-9][0-9]*)$/);
      if (!match) return;
      const target = `${base}_l${match[1]}`;
      if (target === officialRule.target) return;
      const key = `${officialRule.cluster}:${target}:${endpoint}:${officialRule.op}:${officialRule.cmd || officialRule.attr || 0}`;
      if (aliases.has(key)) return;
      aliases.set(key, {
        ...officialRule,
        target,
        aliasOf: String(officialRule.target || ''),
      });
    };

    for (const exp of exposes) {
      const raw = String(exp && exp.property || '');
      const route = routePropertyForExpose(exp, endpoints, meta);
      if (!route.endpoint) continue;
      if (propertyMatchesExpose(raw, 'brightness', endpoints)) {
        const official = officialRules.find(rule => rule.cluster === hex16(0x0008) && rule.target === route.property && rule.endpoint === route.endpoint);
        if (official) addAlias('brightness', official);
      }
      if (propertyMatchesExpose(raw, 'color_temp', endpoints)) {
        const official = officialRules.find(rule => rule.cluster === hex16(0x0300) && rule.target === route.property && rule.endpoint === route.endpoint);
        if (official) addAlias('color_temp', official);
      }
      if (propertyMatchesExpose(raw, 'color', endpoints) ||
          /^(?:color_xy|color_hs)(?:_|$)/.test(raw)) {
        const official = officialRules.find(rule => rule.cluster === hex16(0x0300) &&
          (rule.target === route.property || rule.target === 'color_xy') &&
          rule.endpoint === route.endpoint);
        if (official) addAlias('color_xy', official);
      }
      // color_xy is commonly endpoint-less in upstream exposes. Bind the
      // alias to every endpoint that actually declares XY capability.
      if (raw === 'color' || raw === 'color_xy' || raw.startsWith('color_xy_')) {
        const caps = deriveEndpointCapabilities(prep, endpoints, exposes, [], officialRules, []).byEndpoint;
        for (const [epName, epId] of Object.entries(endpoints)) {
          if (!(caps[epId] & ENDPOINT_CAP_COLOR_XY)) continue;
          const official = officialRules.find(rule => rule.cluster === hex16(0x0300) &&
            rule.endpoint === epId &&
            (rule.target === 'color_xy' || String(rule.target).startsWith('color_xy_')));
          if (official) addAlias('color_xy', official);
          void epName;
        }
      }
      if (propertyMatchesExpose(raw, 'position', endpoints)) {
        const official = officialRules.find(rule => rule.cluster === hex16(0x0102) && rule.target === route.property && rule.endpoint === route.endpoint);
        if (official) addAlias('position', official);
      }
      if (propertyMatchesExpose(raw, 'occupied_heating_setpoint', endpoints) ||
          propertyMatchesExpose(raw, 'current_heating_setpoint', endpoints)) {
        const official = officialRules.find(rule => rule.cluster === hex16(0x0201) &&
          rule.target === route.property && rule.endpoint === route.endpoint &&
          rule.op === 'WRITE_ATTRIBUTE');
        if (official) addAlias('target_temperature', official);
      }
      if (propertyMatchesExpose(raw, 'system_mode', endpoints)) {
        const official = officialRules.find(rule => rule.cluster === hex16(0x0201) && rule.target === route.property && rule.endpoint === route.endpoint);
        if (official) addAlias('system_mode', official);
      }
    }
    for (const alias of aliases.values()) rules.push(alias);
  }

  function routeForRule(key, tz) {
    const explicitEndpoints = Array.isArray(tz.endpoints) ? tz.endpoints : [];
    const enforce = prep.meta && prep.meta.multiEndpointEnforce && typeof prep.meta.multiEndpointEnforce === 'object'
      ? prep.meta.multiEndpointEnforce[key]
      : undefined;
    const enforceEndpoint = resolveEndpoint(enforce, endpoints);
    if (explicitEndpoints.length > 0) {
      const routes = [];
      for (const endpointName of explicitEndpoints) {
        const endpoint = resolveEndpoint(endpointName, endpoints);
        const property = stateExposedRouteForKey(key)
          ? canonicalStateExpose(stateItems.find(exp => String(exp.property) === key) || {property: key, endpoint: endpointName}, endpoints).property
          : endpointProperty(key, String(endpointName), prep.meta);
        routes.push({ property, endpoint: endpoint || 0 });
      }
      return routes;
    }
    if (enforceEndpoint > 0) {
      return [{ property: endpointProperty(key, endpointNameForId(endpoints, enforceEndpoint), prep.meta), endpoint: enforceEndpoint }];
    }
    const exposedRoutes = stateExposedRouteForKey(key)
      ? exposeRoutesForBase(key, true)
      : exposeRoutesForBase(key, false);
    if (exposedRoutes.length > 0) return exposedRoutes;
    return [{ property: key, endpoint: 0 }];
  }

  const stateExposedRouteForKey = key => {
    if (key !== 'state' && key !== 'switch') return false;
    return stateItems.length > 0;
  };

  const officialToZigbee = Array.isArray(prep.toZigbee) ? prep.toZigbee : [];
  for (const tz of officialToZigbee) {
    const keys = Array.isArray(tz && tz.key) ? tz.key : [];
    if (keys.length === 0) continue;

    for (const key of keys) {
      const routes = routeForRule(String(key), tz);
      for (const route of routes) {
        const target = String(route.property || key);
        const endpoint = Number(route.endpoint) || 0;

        if (key === 'state' || key === 'switch') {
          if (isDoorLock) {
            addRule({ op: 'COMMAND', target, endpoint, cluster: hex16(0x0101), cmd: hex16(0x00), cmd_on: hex16(0x00), cmd_off: hex16(0x01), scale: 1.0 });
          } else if (!tuyaStateTargets.has(target)) {
            addRule({ op: 'COMMAND', target, endpoint, cluster: hex16(0x0006), cmd: hex16(0x02), cmd_on: hex16(0x01), cmd_off: hex16(0x00), scale: 1.0 });
          }
        } else if (key === 'brightness' || key === 'brightness_percent') {
          addRule({ op: 'COMMAND', target, endpoint, cluster: hex16(0x0008), cmd: hex16(0x04), scale: 1.0 });
        } else if (key === 'color_temp' || key === 'color_temp_percent') {
          addRule({ op: 'COMMAND', target, endpoint, cluster: hex16(0x0300), cmd: hex16(0x0A), scale: 1.0 });
        } else if (key === 'color' || key === 'color_xy' || key === 'color_hs') {
          const colorTarget = target === key ? 'color_xy' : target;
          if (endpoint > 0) {
            addRule({ op: 'COMMAND', target: colorTarget, endpoint, cluster: hex16(0x0300), cmd: hex16(0x07), scale: 1.0 });
          } else {
            // In multiEndpoint mode ZHC may expose color_xy once while
            // the physical color control lives on one or more endpoints.
            // Expand it across every endpoint with XY capability; the
            // canonical color_xy field remains for Z2M compatibility.
            const xyEndpoints = [...new Set(Object.values(endpoints).filter(id =>
              typeof id === 'number' && id > 0 &&
              ((deriveEndpointCapabilities(prep, endpoints, exposes, [], rules, []).byEndpoint[id] || 0) & ENDPOINT_CAP_COLOR_XY) !== 0))];
            if (xyEndpoints.length === 0) {
              addRule({ op: 'COMMAND', target: colorTarget, endpoint: 0, cluster: hex16(0x0300), cmd: hex16(0x07), scale: 1.0 });
            } else {
              for (const xyEndpoint of xyEndpoints) {
                addRule({ op: 'COMMAND', target: colorTarget, endpoint: xyEndpoint, cluster: hex16(0x0300), cmd: hex16(0x07), scale: 1.0 });
              }
            }
          }
        } else if (key === 'position' || key === 'cover') {
          addRule({ op: 'COMMAND', target, endpoint, cluster: hex16(0x0102), cmd: hex16(0x05), scale: 1.0, coverInverted: prep.meta && prep.meta.coverInverted === true });
        } else if (key === 'occupied_heating_setpoint' || key === 'current_heating_setpoint') {
          addRule({ op: 'WRITE_ATTRIBUTE', target, endpoint, cluster: hex16(0x0201), attr: hex16(0x0012), datatype: 'int16', scale: 100.0 });
        } else if (key === 'system_mode') {
          addRule({ op: 'WRITE_ATTRIBUTE', target, endpoint, cluster: hex16(0x0201), attr: hex16(0x001C), datatype: 'enum8', scale: 1.0 });
        }
      }
    }
  }

  if (isDoorLock) {
    addRule({ op: 'COMMAND', target: 'lock', endpoint: 0, cluster: hex16(0x0101), cmd: hex16(0x00), cmd_on: hex16(0x00), cmd_off: hex16(0x01), scale: 1.0 });
    addRule({ op: 'COMMAND', target: 'unlock', endpoint: 0, cluster: hex16(0x0101), cmd: hex16(0x01), cmd_on: hex16(0x00), cmd_off: hex16(0x01), scale: 1.0 });
  }

  addGangAliases(rules, exposes, endpoints, prep.meta);

  return rules;
}

// Process all definitions
const records = [];
const modelIndex = {};
const fingerprintIndex = {};

let processedCount = 0;
let modernExtendCount = 0;
let tuyaDpCount = 0;
let fingerprintCount = 0;

for (let i = 0; i < defs.length; i++) {
  const d = defs[i];
  let prep = null;
  try {
    prep = await zhc.prepareDefinition(d);
  } catch (err) {
    prep = d;
  }

  const model = String(prep.model || d.model || '').trim();
  if (!model) continue;
  const cleanId = value => String(value || '').replace(/\0+$/g, '').trim();

  const vendor = String(prep.vendor || d.vendor || '').trim();
  const description = String(prep.description || d.description || '').trim();

  // Models list
  // ZHC's model fallback only considers definitions that declare
  // zigbeeModel. Fingerprint-only definitions must not become model
  // fallback candidates, otherwise shared IDs such as TS0002 resolve to
  // an unrelated vendor-specific definition.
  // ZHC indexes every definition that can be reached by a modelID key,
  // including fingerprint-only candidates. Keep all of them in the
  // candidate index; only definitions whose zigbeeModel explicitly
  // declares the key are eligible for the official model fallback.
  const declaredModels = declaredModelKeys(prep, d);
  const indexedModelKeys = definitionModelRanks.has(d)
    ? Array.from(definitionModelRanks.get(d).keys())
    : Array.from(declaredModels);
  const modelPriority = buildModelPriorityMap(indexedModelKeys, d);
  const exactModelKeys = definitionExactModelKeys.get(d) || new Set();
  const normalizedModelKeys = definitionNormalizedModelKeys.get(d) || new Set();
  const models = new Set(indexedModelKeys);
  for (const key of normalizedModelKeys) models.add(key);
  const fallbackModelKeys = new Set();
  for (const modelKey of declaredModels) {
    const normalized = normalizeModelKey(modelKey);
    for (const indexed of indexedModelKeys) {
      if (normalizeModelKey(indexed) === normalized) fallbackModelKeys.add(indexed);
    }
  }
  const fallbackModels = Array.from(fallbackModelKeys);
  const exactModels = Array.from(exactModelKeys);
  const normalizedModels = Array.from(normalizedModelKeys);
  const hasZigbeeModel = declaredModels.size > 0;

    // Fingerprints list
  const fingerprints = [];
  // prepareDefinition() can omit metadata-only fingerprint fields (notably
  // endpoint/IEEE constraints) that are present on the original definition.
  // Merge both arrays in official order without duplicating entries.
  const rawFps = [];
  const appendFingerprints = source => {
    if (!Array.isArray(source)) return;
    for (const fp of source) rawFps.push(fp);
  };
  appendFingerprints(d.fingerprint);
  appendFingerprints(prep.fingerprint);
  for (const rawFp of rawFps) {
    const fp = normalizeFingerprint(rawFp);
    // Metadata-only fingerprints (for example KAJPLATS endpoint-only) are
    // valid ZHC definitions and must not be dropped.
    if (fp) {
      fingerprints.push(fp);
    }
  }

  // Remove exact duplicate constraints while retaining the first official
  // occurrence. This is required because prepareDefinition() may reuse or
  // clone the original fingerprint objects.
  const uniqueFingerprints = [];
  const seenFingerprintJson = new Set();
  for (const fp of fingerprints) {
    const key = JSON.stringify(fp);
    if (seenFingerprintJson.has(key)) continue;
    seenFingerprintJson.add(key);
    uniqueFingerprints.push(fp);
  }
  fingerprints.splice(0, fingerprints.length, ...uniqueFingerprints);

  for (const fp of fingerprints) {
    fp.modelPriority = buildFingerprintCandidateRanks(fp.modelID, declaredModels, d);
  }

  // Exposes
  const exposes = parseExposes(prep.exposes || d.exposes);

  // Clusters, Endpoints & IR Rules
  const clusterIds = new Set();
  const endpoints = extractEndpoints(prep, exposes);
  const commandEventIR = generateCommandEventIR(prep, clusterIds, endpoints);
  const fromZigbeeIR = [
    ...generateFromZigbeeIR(prep, clusterIds, endpoints, exposes),
    ...commandEventIR,
  ];
  const toZigbeeIR = generateToZigbeeIR(prep, clusterIds, endpoints, exposes);
  const tuyaDatapoints = extractTuyaDatapoints(prep);
  const endpointCapabilities = deriveEndpointCapabilities(
    prep, endpoints, exposes, fromZigbeeIR, toZigbeeIR, tuyaDatapoints
  );
  const batterySemantics = extractBatterySemantics(prep, exposes, clusterIds);

  // Audit every official fromZigbee converter against the declarative
  // runtime. Unsupported converters do not prevent identification, but
  // they must mark the definition as limited instead of being reported as
  // fully supported.
  const category = classifyCategory(exposes, description, clusterIds);
  const coverageMissing = auditFromZigbeeCoverage(prep, category);

  if (d.extend) modernExtendCount++;
  if (tuyaDatapoints.length > 0) tuyaDpCount++;
  if (fingerprints.length > 0) fingerprintCount += fingerprints.length;

  // Flags: bit0: tuya, bit1: battery, bit2: multiep, bit3: color, bit4: reporting
  let flags = 0;
  const s = (vendor + ' ' + model + ' ' + description).toLowerCase();
  const isTuya = s.includes('tuya') || s.includes('_tz') || clusterIds.has(0xEF00) || tuyaDatapoints.length > 0;
  if (isTuya) flags |= 0x0001;
  const isBattery = category.includes('sensor') || s.includes('battery') || clusterIds.has(0x0001);
  if (isBattery) flags |= 0x0002;
  if (Object.keys(endpoints).length > 1) flags |= 0x0004;
  if (category === 'color_light' || clusterIds.has(0x0300)) flags |= 0x0008;
  if (fromZigbeeIR.length > 0) flags |= 0x0010;
  const hasInbound = fromZigbeeIR.some(rule => !rule.ignore) ||
    tuyaDatapoints.some(dp => !dp.inboundUnsupported);
  const hasOutbound = toZigbeeIR.length > 0 || tuyaDatapoints.length > 0;
  // bits 5..7 are a three-state support descriptor consumed by the
  // firmware. Keep these bits stable; older firmware masks them out.
  if (hasInbound) flags |= 0x0020;
  if (hasOutbound) flags |= 0x0040;
  if (!hasInbound || !hasOutbound || commandEventIR.some(rule => rule.limited)) {
    flags |= 0x0080;
  }

  // Configure reporting & binds
  const binds = Array.from(clusterIds).map(hex16);
  const reporting = fromZigbeeIR.map(f => ({
    cluster: f.cluster,
    attr: f.attr,
    min: f.cluster === hex16(0x0006) ? 0 : 10,
    max: 3600,
    change: 1
  }));

  const filename = `z2m_${crypto.createHash('sha1').update(model).digest('hex').slice(0, 10)}.json`;

  const record = {
    filename,
    model,
    vendor,
    description,
    category,
    matter_type: category,
    homekit_type: category,
    models: Array.from(models),
    declaredModels: Array.from(declaredModels),
    fallbackModels,
    fingerprints,
    modelPriority,
    exactModels,
    normalizedModels,
    hasZigbeeModel,
    flags,
    endpoints,
    endpointCapabilities: endpointCapabilities.named,
    endpointCapabilityBits: endpointCapabilities.byEndpoint,
    fromZigbee: fromZigbeeIR,
    toZigbee: toZigbeeIR,
    tuyaDatapoints,
    batterySemantics,
    configure: { binds, reporting },
    exposes
  };
  // White-label entries override model/vendor/description only after the
  // base definition has already been selected, matching ZHC findByDevice().
  const rawWhiteLabels = [];
  for (const source of [d.whiteLabel, prep.whiteLabel]) {
    if (!Array.isArray(source)) continue;
    for (const item of source) rawWhiteLabels.push(item);
  }
  const uniqueWhiteLabels = [];
  const seenWhiteLabelJson = new Set();
  for (const item of rawWhiteLabels) {
    let key = '';
    try { key = JSON.stringify(item, (_k, value) => value instanceof RegExp ? value.source : value); } catch {}
    if (seenWhiteLabelJson.has(key)) continue;
    seenWhiteLabelJson.add(key);
    uniqueWhiteLabels.push(item);
  }
  const whiteLabels = uniqueWhiteLabels
    .map(w => ({ model: cleanId(w && w.model), vendor: cleanId(w && w.vendor), description: cleanId(w && w.description), fingerprint: (Array.isArray(w && w.fingerprint) ? w.fingerprint : []).map(normalizeFingerprint).filter(Boolean) }))
    .filter(w => w.model || w.vendor || w.description);

  // Runtime routing data. state_lN is a logical UI property; these tables
  // retain the physical ZCL endpoint or Tuya DP selected by ZHC.
  const endpointRoutes = Object.entries(endpoints).map(([name, id]) => ({ name: String(name), endpoint: Number(id) }));
  const stateRoutes = [];
  for (const rule of [...fromZigbeeIR, ...toZigbeeIR]) {
    const target = String(rule.target || '');
    if (!/^state(?:_l[1-9][0-9]*)?$/.test(target)) continue;
    const dp = rule.cluster === hex16(0xEF00) ? Number(rule.attr) : 0;
    if (!stateRoutes.some(r => r.property === target && r.cluster === rule.cluster && r.endpoint === (rule.endpoint || 0) && r.dp === dp)) {
      stateRoutes.push({ property: target, cluster: rule.cluster, endpoint: rule.endpoint || 0, dp });
    }
  }

  record.whiteLabels = whiteLabels;
  record.multiEndpoint = prep.meta && prep.meta.multiEndpoint === true;
  record.multiEndpointSkip = Array.isArray(prep.meta && prep.meta.multiEndpointSkip) ? prep.meta.multiEndpointSkip.map(String) : [];
  record.multiEndpointEnforce = prep.meta && prep.meta.multiEndpointEnforce && typeof prep.meta.multiEndpointEnforce === 'object' ? prep.meta.multiEndpointEnforce : {};
  record.endpointRoutes = endpointRoutes;
  record.stateRoutes = stateRoutes;

  records.push(record);

  // Update indexes
  for (const m of models) {
    modelIndex[m] = filename;
  }
  const seenFingerprintKeys = new Set();
  for (const fp of fingerprints) {
    const key = `${fp.manufacturerName}|${fp.modelID}`;
    if (seenFingerprintKeys.has(key)) continue;
    seenFingerprintKeys.add(key);
    fingerprintIndex[key] = filename;
  }

  processedCount++;
}

console.log(`[IR Extractor] Successfully compiled ${records.length} records.`);
console.log(`  - With modernExtend: ${modernExtendCount}`);
console.log(`  - With Tuya Datapoints: ${tuyaDpCount}`);
console.log(`  - Total Fingerprints: ${fingerprintCount}`);
console.log(`  - Unique Model Keys: ${Object.keys(modelIndex).length}`);
console.log(`  - Unique Fingerprint Keys: ${Object.keys(fingerprintIndex).length}`);

// Write outputs
const ndjson = records.map(r => JSON.stringify(r)).join('\n') + '\n';
fs.writeFileSync(path.join(outDir, 'z2m_bundle.ndjson'), ndjson);

const idxBody = JSON.stringify(modelIndex, null, 2);
fs.writeFileSync(path.join(outDir, 'z2m_index.json'), idxBody);

const fpBody = JSON.stringify(fingerprintIndex, null, 2);
fs.writeFileSync(path.join(outDir, 'z2m_fingerprints.json'), fpBody);

// Audit trail: every DP whose inbound semantics the declarative rule set
// cannot reproduce. The runtime consumes these reports without publishing.
// extractTuyaDatapoints() is called several times per device (rules, toZigbee
// aliases, endpoint capabilities), so the same DP is visited repeatedly.
// Deduplicate on the full audit identity before writing.
const auditSeen = new Set();
const auditLines = [];
for (const entry of inboundAudit) {
  const key = `${entry.model}|${entry.vendor}|${entry.dp}|${entry.property}|${entry.reason}`;
  if (auditSeen.has(key)) continue;
  auditSeen.add(key);
  auditLines.push(JSON.stringify(entry));
}
for (const entry of converterCoverageAudit) {
  const key = `${entry.model}|${entry.vendor}|converter|${entry.reason}|${entry.source}`;
  if (auditSeen.has(key)) continue;
  auditSeen.add(key);
  auditLines.push(JSON.stringify(entry));
}
const auditBody = auditLines.join('\n') + (auditLines.length ? '\n' : '');
fs.writeFileSync(path.join(outDir, 'z2m_vm_unsupported.ndjson'), auditBody);
console.log(`  - Unsupported inbound semantics (consumed, audited): ${auditLines.length}`);

const b = Buffer.from(ndjson);
const ib = Buffer.from(idxBody);

const manifest = {
  format: 'z2m-esp32-manifest-v6',
  version: '6.0.0',
  ir_version: 6,
  generated_at: new Date().toISOString(),
  source: 'zigbee-herdsman-converters',
  source_version: process.env.ZHC_VERSION || zhcPackageVersion,
  bundle: 'z2m_bundle.ndjson',
  sha256: crypto.createHash('sha256').update(b).digest('hex'),
  bytes: b.length,
  index: 'z2m_index.json',
  index_sha256: crypto.createHash('sha256').update(ib).digest('hex'),
  index_bytes: ib.length,
  device_count: records.length,
  model_keys_count: Object.keys(modelIndex).length,
  fingerprint_keys_count: Object.keys(fingerprintIndex).length
};

fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
console.log(`[IR Extractor] Output written to ${outDir}/: z2m_bundle.ndjson (${(b.length/1024/1024).toFixed(2)} MB), z2m_index.json, manifest.json`);

// Some upstream converters schedule timers while probing definitions. The IR
// is fully written at this point, so terminate cleanly instead of waiting for
// unrelated device-side timers that may throw after generation.
process.exit(0);
