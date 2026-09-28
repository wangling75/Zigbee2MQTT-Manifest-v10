#!/usr/bin/env python3
"""
Zigbee2MQTT Z2MB v10 bundle HTTP server for ESP32 gateways.

The generator is the same binary pipeline used by the upstream release
workflow: Node extracts IR from zigbee-herdsman-converters, then the Python
compiler emits z2m_bundle.bin plus z2m_manifest.json.
"""
import json
import os
import subprocess
import struct
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

PORT = int(os.environ.get('PORT', 8088))
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(ROOT_DIR, 'public')
BUILD_IR_DIR = os.path.join(ROOT_DIR, 'build_ir')
DIST_DIR = os.path.join(ROOT_DIR, 'dist')
MANIFEST_FILE = os.path.join(PUBLIC_DIR, 'z2m_manifest.json')
BUNDLE_FILE = os.path.join(PUBLIC_DIR, 'z2m_bundle.bin')
EXPECTED_FORMAT = 10
EXPECTED_IR = 10


def bundle_is_valid(path):
    """Validate the v10 table layout before serving a cached bundle."""
    try:
        size = os.path.getsize(path)
        if size < 128:
            return False
        with open(path, 'rb') as f:
            header = f.read(128)
        (magic, version, ir_version, device_count, model_off, model_count,
         fp_off, fp_count, records_off, strings_off, total_size, _crc,
         _sha, constraints_off, constraints_count) = struct.unpack(
             '<4sHHIIIIIIIII32sII', header[:84])
        (endpoint_off, endpoint_count, cluster_off, cluster_count,
         white_label_off, white_label_count, _r0, _r1) = struct.unpack(
             '<IIIIIIII', header[84:116])
        vm_code_off, vm_code_size, vm_version, _caps, record_data_size, vm_program_count = \
            struct.unpack('<IIHHII', header[108:128])
        return (
            magic == b'Z2MB' and version == EXPECTED_FORMAT and ir_version == EXPECTED_IR
            and device_count > 0 and model_count > 0 and fp_count > 0
            and model_off == 128 and model_off + model_count * 32 == fp_off
            and fp_off + fp_count * 32 == endpoint_off
            and endpoint_off + endpoint_count * 16 == cluster_off
            and cluster_off + cluster_count * 2 == white_label_off
            and white_label_off + white_label_count * 64 == constraints_off
            and constraints_off + constraints_count * 56 == records_off
            and records_off + record_data_size == vm_code_off
            and vm_code_off + vm_code_size == strings_off
            and strings_off <= total_size == size
            and constraints_count >= fp_count
            and (vm_code_size == 0 or vm_version == 1)
            and vm_program_count <= fp_count + model_count
        )
    except (OSError, struct.error, ValueError):
        return False


def build_binary_bundle():
    os.makedirs(BUILD_IR_DIR, exist_ok=True)
    os.makedirs(DIST_DIR, exist_ok=True)
    os.makedirs(PUBLIC_DIR, exist_ok=True)

    subprocess.run(
        ['node', os.path.join(ROOT_DIR, 'tools', 'z2m_bundle_generator.mjs'), BUILD_IR_DIR],
        cwd=ROOT_DIR, check=True,
    )
    bundle_path = os.path.join(DIST_DIR, 'z2m_bundle.bin')
    manifest_path = os.path.join(DIST_DIR, 'z2m_manifest.json')
    subprocess.run(
        ['python3', os.path.join(ROOT_DIR, 'tools', 'z2m_binary_compiler.py'),
         BUILD_IR_DIR, bundle_path, manifest_path],
        cwd=ROOT_DIR, check=True,
    )

    for src, dst in ((bundle_path, os.path.join(PUBLIC_DIR, 'z2m_bundle.bin')),
                     (manifest_path, MANIFEST_FILE)):
        with open(src, 'rb') as fsrc, open(dst, 'wb') as fdst:
            fdst.write(fsrc.read())

    # Keep both conventional entry names in sync for existing ESP32 URLs.
    with open(MANIFEST_FILE, 'rb') as fsrc:
        manifest_bytes = fsrc.read()
    with open(os.path.join(PUBLIC_DIR, 'manifest.json'), 'wb') as fdst:
        fdst.write(manifest_bytes)

    with open(MANIFEST_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


class ManifestHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if urlparse(self.path).path == '/api/status':
            data = {}
            if os.path.exists(MANIFEST_FILE):
                with open(MANIFEST_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            body = json.dumps({'status': 'online', 'manifest': data}, indent=2).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def do_POST(self):
        if urlparse(self.path).path != '/api/generate':
            self.send_response(404)
            self.end_headers()
            return

        try:
            manifest = build_binary_bundle()
            body = json.dumps({'success': True, 'manifest': manifest}).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            body = json.dumps({'error': str(exc)}).encode('utf-8')
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def run_server():
    # Serve the checked-in bundle by default. A rebuild is explicit (POST
    # /api/generate or FORCE_REBUILD=1), so an outdated local toolchain cannot
    # silently replace a known-good release asset at startup.
    if os.environ.get('FORCE_REBUILD') == '1' or not bundle_is_valid(BUNDLE_FILE):
        print('[*] Rebuilding the v10 bundle from the installed ZHC package...')
        build_binary_bundle()
    else:
        print('[*] Serving the validated prebuilt v10 bundle.')

    httpd = HTTPServer(('', PORT), ManifestHTTPHandler)
    print('==================================================')
    print(f' Z2M Binary Bundle Server is running on port {PORT}')
    print(f' Manifest URL  : http://localhost:{PORT}/z2m_manifest.json')
    print(f' Bundle URL    : http://localhost:{PORT}/z2m_bundle.bin')
    print(f' Status API    : http://localhost:{PORT}/api/status')
    print('==================================================')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nServer stopped.')
        httpd.server_close()


if __name__ == '__main__':
    run_server()
