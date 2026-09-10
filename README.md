# Komari IP 信息插件

为 Komari 主题LuminaPlus提供节点公网 IP 的地理、网络归属、原生性判断和全球延迟信息。插件自身就是后端，不需要单独部署服务，也不要求用户注册第三方账号或购买套餐。

## 功能

- IPv4 / IPv6、国家、地区、城市和坐标
- ASN、运营商、网络类型、网段和主机名
- 原生 IP、广播 IP 和任播 IP 标签
- 香港、东京、新加坡、洛杉矶、温哥华和法兰克福六地延迟
- 基础信息缓存、全球延迟缓存、故障旧缓存和短失败缓存
- 并发请求合并、访问频率限制和每日检测上限
- 中国大陆 IP（`country_code = CN`）自动排除
- 仅 Komari 已登录管理员可触发插件状态、基础查询和全球延迟请求

**中国香港、中国澳门和中国台湾**地区代码 `HK`、`MO`、`TW` 不在排除范围内。主题不展示纯净度、风险指数和污染度。

## 安装

```powershell
npm run package
```

在 Komari 管理后台上传 `dist/komari-ip-info-v0.0.1.zip`，批准 Node.js 兼容层和 HTTP 路由权限，然后启用插件。ZIP 根目录包含 `komari-plugin.json`。

## 数据源与请求流程

基础信息和原生性判断以 [Net.Coffee](https://ip.net.coffee/) 为主源。主源不可用时依次使用 [proxycheck.io v3](https://proxycheck.io/api/) 和 [ipapi.is](https://ipapi.is/) 补充地理与 ASN 信息。

1. 游客访问详情页时，主题不请求插件状态、基础信息或全球延迟接口。
2. 登录后，主题先读取 Komari 后端保存的节点 `region`；能解析为 `CN` 时不调用插件的任何检测接口。
3. 其他节点命中基础信息缓存时直接返回。
4. 地区缺失或无法识别时，未命中的基础查询请求 `https://ip.net.coffee/api/ip/lookup/<IP>` 做兜底判断。
5. Net.Coffee 返回 `CN` 时立即返回排除状态，不执行全球 Ping。
6. Net.Coffee 失败时请求 proxycheck.io；仍失败时请求 ipapi.is。
7. 登录用户打开 IP 信息面板后，复用基础缓存中的原生性结果，只请求一次 Net.Coffee 全球 Ping 接口。
8. 降级基础数据缺少 Net.Coffee 判断时，先查询国家与原生性；如果判定为中国大陆，停止且不发送全球 Ping。

基础信息默认缓存 24 小时，全球 Ping 默认缓存 60 分钟。全球 Ping 的 HTTP 失败会在 5 分钟内直接使用旧结果或返回错误，防止服务波动时反复请求。任一数据源故障时优先返回仍在保留期限内的旧缓存。

每次接口请求的基础查询、降级查询和全球延迟共用 25 秒总预算；预算耗尽后不再发起后续请求。主源响应必须包含匹配的 IP 和有效国家代码，缺失或不匹配时转用备用源。IPv6 先规范化再验证公网范围，映射 IPv4、本地与文档地址不会进入检测链路。缓存结构更新为 `6`，旧缓存会重新生成。

这些是第三方公开接口，免费额度和可用性可能变化。节点 IP 会优先发送给 Net.Coffee；服务故障时可能继续发送给 proxycheck.io 和 ipapi.is。请按部署环境确认其条款和隐私要求。

## 数据来源与致谢

感谢 [Net.Coffee](https://ip.net.coffee/)、[proxycheck.io](https://proxycheck.io/) 和 [ipapi.is](https://ipapi.is/) 提供公开的数据查询能力。本插件仅对接口返回的数据进行读取、缓存和界面适配，相关数据、名称及商标权利归各服务方所有。

如果相关服务方认为本插件的引用或调用方式存在侵权、不合适或不希望被继续使用，请通过 [GitHub Issues](https://github.com/shanyang242/Komari-IP-Info/issues) 联系作者 `shanyang`，收到通知后会及时删除或调整相关内容。

## HTTP API

### 插件状态探测

```http
GET /api/public/ip-info/v1/status
```

主题仅在确认用户已登录后请求此接口。插件不存在、未启用或接口不可达时，主题隐藏“IP 信息”入口；游客不会触发该请求。

### 基础信息

```http
GET /api/public/ip-info/v1/lookup?uuid=<node-uuid>&ip=<public-ip>
```

响应包括 `location`、`network` 和 `classification`。中国大陆 IP 返回 `excluded: true` 和 `excluded_reason: "mainland_china"`，主题会过滤该结果。

### 全球延迟

```http
GET /api/public/ip-info/v1/latency?uuid=<node-uuid>&ip=<public-ip>
```

主题只在登录用户切换到“IP 信息”后调用此接口。接口复用基础查询的原生性结果，正常情况下只向 Net.Coffee 发送一次全球 Ping 请求。

### 管理员刷新

```http
POST /api/admin/ip-info/v1/refresh
Content-Type: application/json

{
  "uuid": "node-uuid",
  "ip": "8.8.8.8",
  "force": true,
  "include_latency": true
}
```

主题中的刷新按钮只提交当前选中的 IPv4 或 IPv6。插件会强制更新该地址的基础信息与六地延迟，不会刷新另一条 IP、其他服务器或整个节点列表。延迟服务临时失败时，基础信息仍会保存并返回，响应中的 `meta.latency_warning` 会说明延迟刷新状态。

### 管理员状态

```http
GET /api/admin/ip-info/v1/status
```

全部查询接口都会在访问数据源前检查 `req.context.principal.roles` 是否包含 `admin`。未登录游客直接收到 `403`，不会向任何第三方数据源发送节点 IP。

这些已鉴权响应统一使用 `Cache-Control: private, no-store`，防止代理或共享浏览器缓存把 IP 信息提供给游客；实际的复用由插件内部缓存和主题查询缓存完成。

## 权限

插件只启用 Node.js 兼容层和 HTTP 路由：

```json
{
  "node": true,
  "allowRoutes": true
}
```

不申请 `allowSystemRPC`、`allowExec`、`allowHooks`、`allowHTMLInject`、`allowListen` 或 `allowAllFileAccess`。缓存仅写入 Komari 分配的 `__storageDir__`。

## 开发

```powershell
npm test
npm run package
```

插件安装版本固定为 `0.0.1`；内部缓存结构通过独立的 `schema_version` 管理。

每次推送到 GitHub 仓库的 `main` 分支后，GitHub Actions 会自动运行测试和打包，并覆盖更新 `v0.0.1` Release 中的 ZIP 附件。版本号保持不变，Release 下载地址也保持稳定。
