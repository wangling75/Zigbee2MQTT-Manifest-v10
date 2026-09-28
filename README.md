# Zigbee2MQTT Manifest Service for ESP32 Gateway

这个仓库把 `zigbee-herdsman-converters` 的设备定义编译成 ESP32 可直接读取的
`Z2MB v10` 二进制 bundle，并通过 GitHub Release、GitHub Pages、Docker 或
普通 HTTP 服务发布给网关。

网关本身不运行 JavaScript，也不启动 Zigbee2MQTT 容器。它只下载经过校验的
二进制定义表，因此以后官方新增设备、修正 fingerprint 或多路开关定义时，
可以只更新 Manifest 服务，不需要重新编译或烧录 ESP32 固件。

## 当前发布物

- 来源：`zigbee-herdsman-converters` `26.112.0`
- 设备定义：`4516`
- model index：`5967`
- fingerprint index / constraint：`2647`
- fingerprint endpoint：`214`
- fingerprint cluster：`997`
- white-label：`977`
- 有歧义 model：`127`
- 重复 fingerprint：`22`
- Bundle 大小：`2132683` 字节（约 `2.03 MiB`）
- Bundle SHA-256：
  `dd9a0d6a389c225ee4eb4c750d95307044403d7c3ea05088bac0f518307aa5e4`
- 能力位：`0x03FF`，包含 `battery_semantics (0x0100)` 与
  `ias_semantics (0x0200)`
- VM 程序：`0`，VM 代码区：`0` 字节

不要用旧的 `26.111.0` Release 资源覆盖当前包。旧资源缺少当前 v10
生成器所需的精确 model 索引和 fingerprint 裁决数据。

## 设备识别逻辑

固件匹配设备时不是只看一个 `modelID`。优先级和约束如下：

1. `manufacturerName + modelID + manufacturerCode/IEEE/endpoint` 等
   fingerprint 约束。
2. 官方定义中的 endpoint、cluster、white-label 约束。
3. `manufacturerName + modelID`。
4. 归一化后的 model 索引。
5. 官方顺序中的 fallback model。
6. 标准 ZCL 能力回退。

同一 `modelID` 对应多个配置时，官方本来就没有唯一答案。编译结果会写入
`ambiguous_model_count` 和 `duplicate_fingerprint_count`，固件遇到歧义会
优先使用 fingerprint 约束；仍无法唯一确定时不会随机选择配置。指纹表按
FNV-1a 32 位哈希排序，运行时用二分查找，不把整张设备表加载进 RAM。

多路开关、灯、传感器、门锁、窗帘、恒温器、插座、遥控器、报警器等不是按
品牌硬编码，而是走同一套官方 fingerprint/model/capability 路径。Tuya DP
只是其中一种声明式规则，不是唯一支持范围。

## 精确重建

仓库中的 `build_ir_frozen/` 是当前发布物的冻结 IR，可用当前生成器重建：

```bash
npm ci
npm run build:bundle
npm run validate:bundle
```

预期结果：

```text
bytes  = 2132683
sha256 = dd9a0d6a389c225ee4eb4c750d95307044403d7c3ea05088bac0f518307aa5e4
devices = 4516
```

`tools/validate_bundle.py` 会检查 magic、格式版本、IR 版本、所有表边界、
manifest 一致性、payload SHA-256、必需能力位和 VM 元数据。

## 上游同步

`tools/z2m_bundle_generator.mjs` 是当前 v10 候选提取器。定时任务每天
查询 `zigbee-herdsman-converters` 最新版本，自动更新 `package.json` 与
`package-lock.json`，构建候选并执行全量门禁。

定时任务中的候选构建命令是：

```bash
npm run ci:candidate
```

候选只有在以下条件全部满足时才能替换 `build_ir_frozen/` 并发布：

- 设备数、model index、fingerprint、endpoint、cluster、white-label 统计合理。
- `battery_semantics` 与 `ias_semantics` 能力位存在。
- 所有表偏移、record 边界、VM 元数据和 SHA-256 校验通过。
- 官方解析器对当前官方包导出的全部 fingerprint/zigbeeModel 探针的选择，
  与仓库内 C++ matcher 完全一致。探针数动态统计，当前为 `7290`；
  门禁要求 `total == 官方探针数`、`agree == total`、`disagree == 0`，
  并保留 `7290` 作为防上游数据异常缩小的下限。
- 开关、多路开关、传感器、门锁、窗帘、温控器、Tuya 和非 Tuya 设备
  全部走同一套官方 fingerprint/model/capability 路径。

任一门禁失败时不会提升候选，也不会覆盖已验证的发布 bundle。成功且
候选二进制与当前 `dist/z2m_bundle.bin` 不一致时，工作流会提交冻结 IR
以及 `data/`、`dist/`、`public/` 发布资产，并发布对应版本 Release。
如果官方版本或元数据变化但没有改变最终二进制，流水线会短路，不重复
提交、发版或重新部署 Pages。之后网关重新同步 Manifest 即可加载新配置，
无需重刷 ESP32。

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
