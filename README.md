# mosdns
fakeip分流大法总教程：https://drive.google.com/drive/u/1/folders/1ldD2XqIrREPgr_CKMSgvYomXgwknpApi  
原版mosdns知识库: https://irine-sistiana.gitbook.io/mosdns-wiki/  
下载: https://github.com/yyysuo/mosdns/releases  
魔改版本配置语法基本无差异，仅添加了一些插件，具体参见fakeip分流大法总教程中mosdns配置 下载预编译文件、更新日志。

### 更新日志
https://github.com/yyysuo/firetv/blob/master/mosdnsconfigupdate/mosdns2026%E6%9B%B4%E6%96%B0%E6%97%A5%E5%BF%97

2026年3月27日增加ebpf过期缓存功能

### 手动保存个性化配置

1. gen/top_domains.txt
2. rule文件夹
3. config_overrides.json
4. upstream_overrides.json
离线全新安装/在线初始化重置后，可以将上述文件（不要删除对应位置的文件夹，需要按文件覆盖）覆盖至对应位置，即可恢复个性化配置。

### 在线升级配置

1. 备份整个mosdns文件夹
2. web上更新2进制
3. 在系统-配置管理部分
MosDNS 本地工作目录填入自己的mosdns配置所在目录，比如/cus/mosdns
远程配置下载 URL (ZIP)填入：https://raw.githubusercontent.com/yyysuo/firetv/refs/heads/master/mosdnsconfigupdate/mosdns20251225allup.zip
然后点击：应用远程配置，mosdns自动重启。

### 在线初始化重置

1. 备份整个mosdns文件夹
2. web上更新2进制
3. 在系统-配置管理部分  
   MosDNS 本地工作目录填入自己的mosdns配置所在目录，比如 `/cus/mosdns`  
   远程配置下载 URL (ZIP)填入：`https://raw.githubusercontent.com/yyysuo/firetv/refs/heads/master/mosdnsconfigupdate/mosdns1225all.zip`  
   然后点击：应用远程配置，mosdns自动重启。
4. 在web ui上按自己的需求调整功能开关部分。
5. 在web ui上按mosdns配置说明填写SOCKS5/ECS IP部分、上游DNS设置、其它设置。

### 离线全新安装

1. 这里下载对应自己架构的2进制，比如放入 `/cus/bin/`  
   https://github.com/yyysuo/mosdns/releases
2. 这里下载全量初始化配置，比如解析至 `/cus/mosdns/` 下  
   https://raw.githubusercontent.com/yyysuo/firetv/refs/heads/master/mosdnsconfigupdate/mosdns1225all.zip
3. 运行命令
   ```bash
   /cus/bin/mosdns start -c /cus/mosdns/config_custom.yaml -d /cus/mosdns
   ```
4. 在web ui上按自己的需求调整功能开关部分。
5. 在web ui上按mosdns配置说明填写SOCKS5/ECS IP部分、上游DNS设置、其它设置。

### mosdns配置说明：

- 远程下载的mosdns配置为通用模板，需要自行修改上游dns、socks5代理等相关信息。
- 建议为foreign组3个上游分别填入socks5，同时设置SOCKS5/ECS IP板块的socks5。
- 此处信息存储于运行目录的 `config_overrides.json`、`upstream_overrides.json` 中。  

**上游DNS设置的说明**

- 预设了所有的dns，一般只需要打开和关闭，不需要新增。
- domestic为国内组，foreign为国外组，cnfake和nocnfake组只能设置1个上游。
- 阿里私享DOH不需要可删除，开启需要设置相应的账户信息及ECS Client IP，可填入这里显示的ipv4 ip：https://ipw.cn/。
- 需要将预设的运营商dns更改为自己的运营商dns。
- foreign所属组共3个上游，需要填入socks5代理，否则将直连，或者遵循mosdns所在操作系统的系统代理。
- 上游dns中的mihomo需要设置为自己的mihomo dns入站
- 上游dns中的sing-box需要设置为自己的sing-box dns入站

**其它设置说明**
- 如果不需要nft功能，此处将不需要任何的配置，原条目可删除。
- 原值 (查找)为配置模板中预设的初始值（不要修改！），新值 (替换)将替换初始值在mosdns启动时加载，不会回写至配置模板，状态中的数字代表配置中有多少处原值被替换。。
- nft功能说明：https://raw.githubusercontent.com/yyysuo/firetv/refs/heads/master/mosdnsconfigupdate/mosdns%20nft%E8%A7%84%E5%88%99%E6%B7%BB%E5%8A%A0%E5%8A%9F%E8%83%BD%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E

#### 如何查找sing-box dns入站：
  如果 sing-box 和 mosdns 在一个虚拟机上，新值去你 sing-box 的配置文件中去找，找到 `inbounds` 部分类似这样的配置：
  ```json
  "inbounds": [
    {
      "type": "direct",
      "tag": "in-dns",
      "sniff": false,
      "listen": "::",
      "listen_port": 7800
    },
  ```
  那sing-box dns入站就是： `udp://127.0.0.1:7800`。

#### mosdns ui 系统-高级设置-SOCKS5/ECS IP部分说明：

1. 此处socks5代理仅对规则文件下载、mosdns更新生效，不对上游DNS生效。
2. **socks5 代理**：填写可用的socks5代理，不支持用户名密码。
3. **ECS IP**：打开 https://ipw.cn/ ，如果有ipv4、ipv6的ip，就把ipv6 ip填入ECS IP框中；如果没有，就写ipv4地址。

### 本项目mosdns配置解析流程



![mosdns解析流程](https://github.com/user-attachments/assets/c4b0c10c-7c99-4dbb-922c-64de1d566f98)



<img width="1559" height="896" alt="image" src="https://github.com/user-attachments/assets/3a5d7f92-ee34-4612-a0c0-f97fbc2f2b59" />

<img width="1545" height="852" alt="image" src="https://github.com/user-attachments/assets/4c8c72ae-636a-42e3-a645-059e4ca89f12" />

<img width="1558" height="902" alt="image" src="https://github.com/user-attachments/assets/e60b8530-e9fb-4792-a711-6d5e03b11f4f" />

<img width="1586" height="896" alt="image" src="https://github.com/user-attachments/assets/9236b9b5-6058-43fa-899a-a669c04372b5" />

<img width="1551" height="899" alt="image" src="https://github.com/user-attachments/assets/80a53a63-957b-4b04-abe5-d0976972da11" />

<img width="1558" height="904" alt="image" src="https://github.com/user-attachments/assets/2318f836-efe8-45aa-9dbd-b6faffaa11fa" />

<img width="1568" height="900" alt="image" src="https://github.com/user-attachments/assets/1ff7afe5-abeb-413d-88e3-98481a28c8a9" />

<img width="1564" height="906" alt="image" src="https://github.com/user-attachments/assets/83e7c8fe-7cbb-474a-8f71-a52fc1f8dba3" />

<img width="1561" height="893" alt="image" src="https://github.com/user-attachments/assets/e91b7a6e-53e3-4be9-ae54-e750843292c6" />

## 版本与下载

- 版本号规范（自 2025-11-06 起）
  - 统一为 `v5-ph-srs-YYYYMMDD-<shortsha>`，例如：`v5-ph-srs-20251104-4f2f1c9`。
  - 可执行文件内的 `./mosdns version` 输出与发布标签一致。

- 获取最新稳定版
  - 通过 GitHub `releases/latest` 固定入口下载：
    - `.../releases/latest/download/mosdns-linux-amd64.zip`
    - `.../releases/latest/download/mosdns-linux-amd64-v3.zip`
    - `.../releases/latest/download/mosdns-linux-arm64.zip`
    - `.../releases/latest/download/mosdns-darwin-amd64.zip`
    - `.../releases/latest/download/mosdns-darwin-arm64.zip`
    - `.../releases/latest/download/mosdns-windows-amd64.zip`
    - `.../releases/latest/download/mosdns-windows-amd64-v3.zip`
    - `.../releases/latest/download/mosdns-windows-arm64.zip`

- 获取指定版本
  - 将 `<TAG>` 替换为发布页中的完整标签，例如 `v5-ph-srs-20251104-4f2f1c9`：
    - `.../releases/download/<TAG>/mosdns-<os-arch>.zip`

## 内置在线更新

- 前端：在“系统 → 版本与更新”可手动强制检查、立即更新或强制更新；支持自动检查间隔设置。
- API：
  - `GET /api/v1/update/status` 查询状态
  - `POST /api/v1/update/check` 强制刷新状态
  - `POST /api/v1/update/apply` 执行更新（JSON: `{ "force": true|false }`）
- 行为：
  - 下载匹配当前平台的压缩包，解压并原地覆盖二进制（Unix 保留可执行位；Windows 写入 `.new` 并提示手动替换）。
  - 安装成功后自动调用 `POST http://127.0.0.1:9099/api/v1/system/restart` 自重启（Unix）；Windows 因文件锁定不执行自重启。

## 重要变更：移除固定 tag 回退

- 自 2025-11-06 起，客户端仅使用 `releases/latest` 获取更新信息；不再回退到固定 tag（例如 `v5-ph-srs`）。
- 发布侧无需再向固定 tag 上传资产；请使用版本化标签发布即可。
- 

## adguard_rule 插件：AdGuard Home 同源过滤引擎

本分支把 `adguard_rule` 的规则解析从自写的正则匹配器换成 AdGuard 官方
[`github.com/AdguardTeam/urlfilter`](https://github.com/AdguardTeam/urlfilter) DNS 引擎——
即 AdGuard Home 自身使用的同一个库，过滤语义与 AGH 对齐。

### 解决的问题

旧解析器只识别四种写法：`||domain^`、`@@||domain^`、`/regex/`、裸域名。带修饰符的规则
（`$important`、`$badfilter`、`$client`、`$dnstype`、`$denyallow`）、路径规则、hosts 双列规则
全部被静默丢弃。以 43 条用户规则实测：旧版只解析 10 条，导致 `@@||pv.sohu.com^$important`
这类白名单失效（`pv.sohu.com`、`t-e.flyme.cn`、`umid.orion.meizu.com` 被误杀成 NXDOMAIN），
`||log.mmstat.com^$important` 这类拦截规则则漏拦。

新引擎在同一份规则集上加载 399965 条（旧版 291264 条），与 AGH 逐域比对 170 个样本 0 差异。

### 两种用法

matcher 模式（兼容旧配置，只按域名匹配，不含 qtype / `$client` 语义）：

```yaml
- matches: qname $adguard
  exec: reject 3
```

exec 模式（推荐，能拿到 qtype 与客户端地址，`$dnstype` / `$client` / `$dnsrewrite` / hosts 全部生效）：

```yaml
- tag: adguard
  type: adguard_rule
  args:
    dir: /etc/mosdns/adguard
    block_mode: null_ip   # 可选 null_ip（默认，A→0.0.0.0、AAAA→::）| nxdomain | refused
```

```yaml
- exec: $adguard
- matches: has_resp
  exec: accept
```

### 注意事项

- `$important` 例外规则按域名规则本身生效：`@@||sohu.com^` 会放行全部子域，
  只想放行单个子域要写 `@@||pv.sohu.com^`，与 AGH 完全一致。
- 规则重载失败时保留旧引擎，不会瞬间失去过滤能力。
- 元素隐藏规则（`##`、`#?#`、`$$`）在 DNS 层无意义，加载时跳过。

## 查询日志落盘（对齐 AdGuardHome querylog）

默认仍是纯内存环形缓冲（重启清零）。开启落盘后，日志按天写入 JSONL，重启自动回填：

```json
// <config_dir>/audit_settings.json
{
  "capacity": 100000,
  "file_enabled": true,
  "file_dir": "audit",
  "retention_days": 7,
  "file_max_mb": 64
}
```

- `file_dir` 留空时为 `<config_dir>/audit`，相对路径按配置目录解析
- 文件名 `audit-YYYYMMDD.jsonl`，超过 `file_max_mb` 滚动为 `audit-YYYYMMDD-1.jsonl`
- 启动时读取磁盘最近 `capacity` 条回填内存，面板与 API 在重启后仍能看到历史
- 超过 `retention_days` 的文件在启动时清理
- 写盘走独立协程 + 有界队列，队列满时丢日志而不阻塞查询

**另外必须在 server 上开审计**，否则日志不会产生：

```yaml
- type: udp_server
  args: { entry: main, listen: ":53", enable_audit: true }
```

## 版本号约定

`VERSION` 文件写「基线-补丁集」，构建时自动拼上日期与短 SHA：

```
VERSION 内容        v5.3.4-agh1
实际二进制版本      v5.3.4-agh1-20261103-be9fb22
                      └基线┘ └补丁┘ └日期┘  └SHA┘
```

- **基线**：跟随上游 IrineSistiana/mosdns 的 tag，便于判断代码年代
- **补丁集**：本分支自有特性编号，功能或行为变更时递增（`agh1` → `agh2`）
- 日期与 SHA 由 `make build` / CI 注入，不手写
- `make version` 可预览当前会注入的版本号

## 容器镜像

`.github/workflows/docker.yml` 在推 tag / 推 main / 手动触发时构建 `linux/amd64` + `linux/arm64`
镜像并推送 GHCR：

```
ghcr.io/ccwssy/mosdns:<版本>      例如 v5.3.4-agh1-20261103-be9fb22
ghcr.io/ccwssy/mosdns:latest
```

本地构建：`make docker`（可用 `IMAGE=...` 覆盖镜像名）。
