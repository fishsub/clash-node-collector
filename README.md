# clash-node-collector

本地运行的公开代理订阅收集器。从多个 GitHub 订阅源拉取节点，支持 **Base64 / 纯 URI 列表 / Clash YAML**，按 **IP + 端口** 去重后输出标准 Clash / Mihomo 订阅文件。

> 仅供学习与自用测试。免费公开节点存活率通常很低，请注意安全与合规。

## 功能

- 内置多个公开订阅源（可在 `collect.js` 的 `SOURCES` 中增删）
- 自动识别 Base64、`vmess://` / `vless://` / `trojan://` / `ss://` / `hysteria2://` 等
- 解析 Clash / Mihomo YAML 中的 `proxies`
- **按 IP + 端口严格去重**（同一地址端口只保留一个节点）
- 生成可用的 `proxies` + `PROXY`(select) + `AUTO`(url-test) + 简单 `rules`

## 环境

- Node.js **18+**（使用原生 `fetch`）

## 安装与运行

```bash
git clone https://github.com/fishsub/clash-node-collector.git
cd clash-node-collector
npm install
npm start
```

输出文件：

```
output/clash.yaml
```

直接导入 [Clash Verge](https://github.com/clash-verge-rev/clash-verge-rev) / Clash Meta / Mihomo 即可。

## 配置

在 `collect.js` 顶部可修改：

| 变量 | 说明 | 默认 |
|------|------|------|
| `SOURCES` | 订阅源列表 | 内置 11 个 |
| `MAX_PROXIES` | 写入 YAML 的最大节点数 | `2500` |
| `TIMEOUT_MS` | 单源请求超时 | `25000` |

## 定时任务示例

```bash
# 每天 6:00 拉取一次
0 6 * * * cd /path/to/clash-node-collector && /usr/bin/node collect.js >> /tmp/clash-collector.log 2>&1
```

## License

[MIT](./LICENSE)
