// Differential matcher test.
//
// Consumes the NUL-safe TSV produced by
// Zigbee2MQTT-Manifest/tools/export_expect.mjs, where every probe was answered
// by the *official* zigbee-herdsman-converters resolver. Our C++ matcher must
// reproduce those selections exactly across all device categories.
//
// Field order (tab separated):
//   modelID_hex mfg_hex manufacturerID date_hex sw_hex
//   hw app stack zcl power type expected_model_hex
#include "converter_bundle.h"
#include "converter_matcher.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>

using namespace z2m;

static std::string fromHex(const std::string& h) {
    if (h == "-" || h.empty()) return std::string();
    std::string out;
    out.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return std::string();
        out.push_back((char)((hi << 4) | lo));
    }
    return out;
}

static std::vector<std::string> split(const std::string& line, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : line) {
        if (c == sep) { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(cur);
    return out;
}

// Minimal parser for the endpoint JSON emitted by export_expect.mjs:
// [{"ID":1,"deviceID":5,"profileID":260,"inputClusters":[...],"outputClusters":[...]}]
static long jsonNum(const std::string& s, size_t& i) {
    while (i < s.size() && !(s[i] == '-' || (s[i] >= '0' && s[i] <= '9'))) i++;
    bool neg = false;
    if (i < s.size() && s[i] == '-') { neg = true; i++; }
    long v = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') { v = v * 10 + (s[i] - '0'); i++; }
    return neg ? -v : v;
}

static std::vector<uint16_t> jsonArray(const std::string& s, size_t& i) {
    std::vector<uint16_t> out;
    if (i >= s.size() || s[i] != '[') return out;
    i++;
    while (i < s.size() && s[i] != ']') {
        if (s[i] == '-' || (s[i] >= '0' && s[i] <= '9')) {
            out.push_back((uint16_t)jsonNum(s, i));
        } else {
            i++;
        }
    }
    if (i < s.size()) i++; // ']'
    return out;
}

static std::vector<EndpointInfo> parseEndpoints(const std::string& s) {
    std::vector<EndpointInfo> eps;
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] != '{') { i++; continue; }
        i++;
        EndpointInfo ep;
        bool hasId = false;
        while (i < s.size() && s[i] != '}') {
            if (s[i] == '"') {
                size_t j = s.find('"', i + 1);
                if (j == std::string::npos) break;
                const std::string key = s.substr(i + 1, j - i - 1);
                i = j + 1;
                while (i < s.size() && s[i] != ':') i++;
                if (i < s.size()) i++;
                if (key == "ID") { ep.ep_id = (uint8_t)jsonNum(s, i); hasId = true; }
                else if (key == "deviceID") { ep.device_id = (uint16_t)jsonNum(s, i); }
                else if (key == "profileID") { ep.profile_id = (uint16_t)jsonNum(s, i); }
                else if (key == "inputClusters") { ep.input_clusters = jsonArray(s, i); }
                else if (key == "outputClusters") { ep.output_clusters = jsonArray(s, i); }
            } else {
                i++;
            }
        }
        if (i < s.size()) i++; // '}'
        if (hasId) eps.push_back(ep);
    }
    return eps;
}

int main(int argc, char** argv) {
    const char* bundlePath = argc > 1 ? argv[1] : "data/z2m_bundle.bin";
    const char* tsvPath = argc > 2 ? argv[2] : "/tmp/expect.tsv";

    auto reader = std::make_shared<FileBundleReader>(bundlePath);
    if (!reader->isOpen()) { std::fprintf(stderr, "cannot open %s\n", bundlePath); return 2; }
    ConverterBundle bundle;
    if (!bundle.load(reader)) { std::fprintf(stderr, "cannot load bundle\n"); return 2; }
    ConverterMatcher matcher(bundle);

    std::ifstream in(tsvPath);
    if (!in) { std::fprintf(stderr, "cannot open %s\n", tsvPath); return 2; }

    size_t total = 0, agree = 0, disagree = 0;
    std::vector<std::string> samples;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto f = split(line, '\t');
        if (f.size() < 12) continue;
        DeviceInterview iv;
        iv.model_id = fromHex(f[0]);
        iv.manufacturer_name = fromHex(f[1]);
        iv.manufacturer_code = (uint16_t)std::atoi(f[2].c_str());
        iv.date_code = fromHex(f[3]);
        iv.software_build_id = fromHex(f[4]);
        iv.hardware_version = (int16_t)std::atoi(f[5].c_str());
        iv.application_version = (int16_t)std::atoi(f[6].c_str());
        iv.stack_version = (int16_t)std::atoi(f[7].c_str());
        iv.zcl_version = (int16_t)std::atoi(f[8].c_str());
        // ZHC fingerprints express powerSource as a ZCL enum *name*; the
        // bundle stores the numeric enum. Mirror the compiler's mapping.
        {
            const std::string& ps = f[9];
            if (ps == "Mains (single phase)") iv.power_source = 1;
            else if (ps == "Mains (3 phase)") iv.power_source = 2;
            else if (ps == "Battery") iv.power_source = 3;
            else if (ps == "DC Source") iv.power_source = 4;
            else if (ps == "Emergency mains constantly powered") iv.power_source = 5;
            else if (ps == "Emergency mains and transfer switch") iv.power_source = 6;
            else if (ps.empty() || ps == "-") iv.power_source = 0xFF;
            else iv.power_source = (uint8_t)std::atoi(ps.c_str());
        }
        // f[10] carries the ZHC logical type name; fingerprints constrain on
        // it (FingerprintConstraint: 1=Router, 2=EndDevice).
        if (f[10] == "Router") iv.logical_type = 1;
        else if (f[10] == "EndDevice") iv.logical_type = 2;
        else iv.logical_type = 0;
        const std::string expect = fromHex(f[11]);
        if (f.size() > 12) {
            const std::string epsJson = fromHex(f[12]);
            iv.endpoints = parseEndpoints(epsJson);
        }

        MatchedConverter out;
        bool ok = matcher.matchDevice(iv, out);
        const std::string got = ok ? out.model : std::string();
        total++;
        if (got == expect) {
            agree++;
        } else {
            disagree++;
            if (samples.size() < 1000) {
                char buf[512];
                std::snprintf(buf, sizeof(buf),
                              "model='%s' mfg='%s' expected='%s' got='%s'",
                              iv.model_id.c_str(), iv.manufacturer_name.c_str(),
                              expect.c_str(), got.c_str());
                samples.push_back(buf);
            }
        }
    }

    for (const auto& s : samples) std::printf("DIFF %s\n", s.c_str());
    std::printf("total=%zu agree=%zu disagree=%zu\n", total, agree, disagree);
    return disagree == 0 ? 0 : 1;
}
