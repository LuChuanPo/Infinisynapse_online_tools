# Infinisynapse Tools — 部署说明

工具已从 `/tools/` 迁移到 `/online_tools/`（客户的 `/tools` 已被 Agent Tools 页占用）。
所有 canonical / og:url / sitemap / 面包屑 / 站内链接都已指向
`https://infinisynapse.com/online_tools/...`，且**页面 URL 一律不带结尾斜杠**
（如 `…/online_tools/db-compatibility-checker`）。
`vercel.json` 里 `trailingSlash:false + cleanUrls:true` 会在边缘强制这一形式：
带斜杠的访问会 308 跳到无斜杠版本，和 canonical 一致。
导航里的 "Agent Tools" 链接（`infinisynapse.com/tools`，无斜杠）保持不动，仍指向客户原有页面。

## 结构
```
/                         ← 部署根（你的 Vercel）
  api/check-connection.js     真实 serverless 函数（/api/check-connection）
  online_tools/               所有对外页面
    index.html                  → /online_tools/
    nl2sql-query-tester/
    roi-calculator/
    sql-complexity-checker/
    db-compatibility-checker/   调用 /online_tools/api/check-connection
    sitemap.xml  robots.txt
  vercel.json                 把 /online_tools/api/check-connection 重写到 /api/check-connection
  local-server.js             本地预览：npm i && npm run dev
```

## 第一步：部署到你自己的 Vercel
1. 代码推到 GitHub。
2. Vercel → New Project → 导入仓库 → Deploy（`pg`、`mysql2` 会自动安装）。
3. 自测：`https://<你的项目>.vercel.app/online_tools/` 和
   `.../online_tools/db-compatibility-checker/`（点测试，确认 API 正常）。

## 第二步：客户域名指向（子目录，保留前缀）
客户只配一条反向代理，把 `/online_tools/*` 原样转发到你的 Vercel（**保留** `online_tools` 前缀，不要 strip）：

- 客户用 Vercel，客户项目 `vercel.json`：
  ```json
  { "rewrites": [
    { "source": "/online_tools/:path*", "destination": "https://<你的项目>.vercel.app/online_tools/:path*" }
  ]}
  ```
- 客户用 Nginx：直接用同目录下的完整配置文件 `infinisynapse-online_tools.nginx.conf`
  （已含 SNI、跳转回写、POST 透传、超时等),把里面的 `location ^~ /online_tools { ... }`
  整段粘进 `infinisynapse.com` 的 server 块,`nginx -t` 通过后 `nginx -s reload`：
  ```nginx
  location ^~ /online_tools {
    proxy_pass https://infinisynapse-online-tools.vercel.app;
    proxy_set_header Host infinisynapse-online-tools.vercel.app;
    proxy_ssl_server_name on;
    proxy_redirect https://infinisynapse-online-tools.vercel.app/ /;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_http_version 1.1;
    proxy_set_header   Connection "";
  }
  ```
- 客户用 Cloudflare：加一条 Origin Rule / Worker，把 `infinisynapse.com/online_tools/*`
  代理到 `<你的项目>.vercel.app/online_tools/*`。

客户无需开任何端口、无需跑服务器。配完访问
`https://infinisynapse.com/online_tools/db-compatibility-checker/` 应与 Vercel 上一致。

## 第三步：Google Search Console
内容长在 `infinisynapse.com` 下，所以用**客户的** GSC 资源（让客户把你加为用户）。
1. 资源类型选 URL prefix：`https://infinisynapse.com/`（客户通常已验证）。
2. Sitemaps → 提交 `https://infinisynapse.com/online_tools/sitemap.xml` → 等状态 Success。
   - 若报"无法获取"，先在浏览器确认该 URL 能直接打开（多半是第二步代理没配好）。
3. URL Inspection 逐条贴 5 个页面 → Request Indexing，催收最快。
4. 让客户从主站高权重页面（首页/导航/相关文章）加内链到这些工具页，帮助发现与收录。

注意：`robots.txt` 只有放在域名根 `infinisynapse.com/robots.txt` 才被爬虫当权威读取，
那个文件归客户控制。本包内的 `online_tools/robots.txt` 仅作参考——
收录靠 GSC 直接提交 sitemap 即可，无需依赖它。可选：请客户在根 robots.txt 加一行
`Sitemap: https://infinisynapse.com/online_tools/sitemap.xml`。

## 安全（db-compatibility-checker）
访客会输入数据库地址/账号/密码，由你的 serverless 函数代连。当前状态：
- ✅ **SSRF 防护已内置**：`api/check-connection.js` 会先解析目标域名，拒绝任何指向
  私有/保留地址的目标（`127.0.0.0/8`、`10/8`、`172.16/12`、`192.168/16`、
  `169.254/16`（含云元数据 `169.254.169.254`）、`100.64/10`、`::1`、`fc00::/7`、
  `fe80::/10`、IPv4-mapped IPv6 等），并对 `localhost` / `*.internal` / `*.local`
  等内部名直接拦截。校验通过后**连接会 pin 到已验证的 IP**，因此 DNS rebinding 和
  十进制/八进制/十六进制 IP 绕过也一并被挡。被拦截时返回 `400 BLOCKED_TARGET`。
- ✅ 凭证不落日志（`console.log` 只打 `host:port`，不含账号密码）。
- ⬜ **限流仍建议加**：避免有人把它当端口扫描器批量滥用。Vercel 上可用
  Edge Middleware + KV，或在函数内做简单 IP 计数。需要的话我可以补。
