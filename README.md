
## GitHub 部署

### 1. 创建仓库

把本目录作为仓库根目录推送到 GitHub：

```bash
git init
git add .
git commit -m "Z2M ESP32 Manifest service"
git branch -M main
git remote add origin https://github.com/<你的账号>/Zigbee2MQTT-Manifest.git
git push -u origin main
```

### 2. 开启 Actions 与 Pages

在仓库 `Settings -> Actions -> General` 允许 Actions 运行。  
在 `Settings -> Pages -> Build and deployment -> Source` 选择
`GitHub Actions`。工作流会自动：

1. 每日检查 `zigbee-herdsman-converters` 最新版本。
2. 构建候选 IR 与 v10 bundle，执行布局和全量 matcher 门禁。
3. 只把已通过验证的候选上传为 Actions Artifact。
4. 发布任务下载同一份 artifact，改名为正式 `z2m_bundle.bin`。
5. 仅在候选二进制变化时提交冻结 IR、`data/`、`dist/` 和 `public/`，
   发布 Release 并部署 Pages。

手动触发入口是 `Actions -> Z2M Binary Bundle v10 CI/CD Pipeline ->
Run workflow`。

### 3. 网关 URL

GitHub Pages 地址通常是：

```text
https://<你的账号>.github.io/Zigbee2MQTT-Manifest/z2m_manifest.json
```

如果使用 Release 资源，可以直接使用：

```text
https://github.com/<你的账号>/Zigbee2MQTT-Manifest/releases/latest/download/z2m_manifest.json
https://github.com/<你的账号>/Zigbee2MQTT-Manifest/releases/latest/download/z2m_bundle.bin
```

在网关 Web 的 Manifest 地址中填写 `z2m_manifest.json` 的完整 URL。网关会
下载并校验同目录的 `z2m_bundle.bin`，通过后替换本地 bundle，并在不重启的
情况下重新匹配已接入设备。

GitHub 下载受限时，固件也支持直接上传本地 `z2m_bundle.bin`。这只影响
下载路径，不改变固件中的哈希和能力校验。

当前 v10 自动流水线以官方 `zigbee-herdsman-converters` 为唯一设备定义来源；
旧版教程中的 `custom_devices.json` 不会由该流水线合并。需要私有设备时，应在
后续版本中单独实现并接入同一套候选门禁，不能假设仅编辑该文件就会自动生效。

### 4. Docker 部署

```bash
docker compose up -d --build
```

默认端口 `8088`：

```text
http://<服务器地址>:8088/z2m_manifest.json
http://<服务器地址>:8088/z2m_bundle.bin
http://<服务器地址>:8088/api/status
```

`POST /api/generate` 会显式重建。默认启动只服务已校验的预构建 bundle，
不会因为本机旧工具链而静默替换发布资产。

## 安全说明

固件当前通过 `WiFiClientSecure::setInsecure()` 下载 HTTPS。传输内容是
加密的，但没有验证服务器证书链。生产环境应优先使用可信域名、Release
哈希和固件自身的 bundle 校验；后续可把 CA 固定或证书校验作为独立固件改进。

## 目录

```text
tools/z2m_bundle_generator.mjs   v10 上游候选 IR 提取器
tools/z2m_binary_compiler.py     IR -> Z2MB v10 编译器
tools/validate_bundle.py         bundle/manifest 独立校验器
tests/run_matcher_diff.py        官方解析器与 C++ matcher 全量差分门禁
tests/runtime/                   自包含 matcher C++ 源码与头文件
build_ir_frozen/                 当前发布物对应的冻结 IR
dist/                            构建输出
public/                          GitHub Pages 静态发布目录
server.py                        HTTP 服务和显式重建 API
docker-compose.yml               本地容器部署
```
