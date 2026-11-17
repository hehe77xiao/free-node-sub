# free-node-sub

从 GitHub 公开仓库收集免费 Clash/V2Ray 节点，自动整理（去重、地区识别、TCP 测活），
导出 **Clash（mihomo）YAML** 与 **sing-box JSON** 订阅文件，并可通过本地文件订阅方式自动更新到
[Satelite](https://github.com/zn0wii/satelite-proxy) 客户端。

## 工作原理

```
GitHub 订阅源 ──抓取──▶ 格式嗅探解码 ──▶ 去重 ──▶ TCP 测活 ──▶ 导出
 sources.yaml          clash/singbox/      dedupe    并发建连     output/
                       base64/明文URI                                    │
                                                                        ▼
                          Satelite 订阅页导入本地文件 + 开启自动定时更新
```

- 每次运行把**固定文件名**重写到 `output/`，Satelite 的「文件订阅」到点自动重读该文件，
  因此**首次手动导入一次后，后续全自动**。

## 安装

```bash
cd free-node-sub
uv sync --all-extras
```

## 使用

```bash
# 完整流水线（抓取 + 去重 + TCP 测活 + 导出）
uv run python -m freenodes update

# 常用参数
uv run python -m freenodes update --max-nodes 500     # 限制导出数量
uv run python -m freenodes update --no-test           # 跳过 TCP 测活（更快）
uv run python -m freenodes update --timeout 5         # 增加超时
uv run python -m freenodes update --sources config/sources.yaml --out output
```

输出文件：

| 文件 | 说明 |
| --- | --- |
| `output/satelite-clash.yaml` | Clash Meta 格式，含 🚀 手动选择 / ⚡ 自动选择 / 各地区 url-test 策略组 |
| `output/satelite-singbox.json` | sing-box `outbounds` 格式（Satelite 默认内核） |
| `output/nodes.json` | 整理后的节点清单（名称/协议/服务器/地区/来源），便于人工核对 |
| `output/meta.json` | 本次运行的统计信息 |

导出兼容性（已用 Satelite 自带内核二进制校验：`mihomo -t` 与 `sing-box check` 均通过）：

- sing-box 导出会跳过它不支持的条目：`ssr` 协议、`xhttp` / `raw` 等传输扩展
  （Satelite 内嵌 sing-box 1.14.1 未编译这些扩展）；非法 `flow` / 指纹 / `packet_encoding` 会被安全省略
- Clash 导出保留全部协议（mihomo 支持 ssr、xhttp 等）
- 两份文件都会被本项目解析器原样读回（回环测试）

## 导入 Satelite（一次性操作）

1. 打开 Satelite → 订阅页 → 新建 → 类型选「本地文件」
2. 选择 `output/satelite-clash.yaml`（推荐，三内核通用）或 `output/satelite-singbox.json`
3. 在该订阅上开启 **自动更新**，间隔建议 ≥ 60 分钟
4. 之后只需要定期运行 `uv run python -m freenodes update`，Satelite 会自动重读文件刷新节点

> 注意：Satelite 自动更新的粒度取决于你设置的间隔；运行本项目与 Satelite 拉取先后无关，
> 下一次拉取总是拿到最新内容。

## 源维护

`config/sources.yaml` 内置了一批实测可用的 GitHub 源，可自由增删；
`raw.githubusercontent.com` 的源会自动尝试 jsDelivr 镜像兜底。

## 开发

```bash
uv run --extra test pytest tests/            # 单元测试
uv run --extra lint ruff check src tests     # lint
uv run --extra lint ruff format <文件/范围>  # 格式化
```

## 免责

节点均来自互联网公开仓库，不保证可用性与安全性，请勿传输敏感信息；免费节点失效快，建议定期测活。仅供学习交流。
