# oauth2-authz-server-go

一个可本地运行的、类 OAuth2/OIDC 的授权服务器，仅依赖 Go 标准库。支持授权码 + PKCE 流程、
RS256 JWT 访问令牌、签名密钥轮换、刷新令牌轮换与重放检测、令牌撤销与失效传播，
所有拒绝均返回**可区分的错误码**并输出判定日志。

## 快速开始

```bash
go build ./...
go test -race ./...
go run ./cmd/server -addr :8080
```

预置客户端与账号：

| 客户端 | 密钥 | 重定向地址 | 允许范围 |
|---|---|---|---|
| `demo-client` | `demo-secret` | `http://localhost:8080/callback`, `http://127.0.0.1:9000/cb` | `openid profile email` |
| `public-client` | （公共客户端，无密钥） | `http://localhost:8080/callback` | `openid profile` |

用户：`alice/wonderland`、`bob/builder`。

## 协议语义

### 端点

| 端点 | 方法 | 说明 |
|---|---|---|
| `/authorize` | GET | 授权码签发。强制 `response_type=code`、PKCE `S256`、精确匹配的重定向地址、范围子集校验。演示用 `user`/`password` 参数完成用户认证。 |
| `/token` | POST | `grant_type=authorization_code`（校验客户端身份、redirect_uri 一致性、PKCE verifier）或 `grant_type=refresh_token`（轮换）。客户端认证优先 HTTP Basic，其次表单字段。 |
| `/userinfo` | GET | 受保护资源。校验 Bearer 令牌签名、有效期（含时钟偏移）、签发方、撤销状态，并要求 `profile` 范围。 |
| `/revoke` | POST | 撤销访问或刷新令牌。 |
| `/jwks.json` | GET | 当前可用于校验的公钥集合（活跃 + 保留期内的历史密钥）。 |
| `/rotate` | POST | 触发签名密钥轮换（本地管理接口）。 |
| `/healthz` | GET | 健康检查。 |

### 授权码约束

- 授权码**一次性**：在 `/token` 出示后立即作废——即使 PKCE 校验失败也作废，防止暴力破解；
  重复使用返回 `invalid_grant:code_unknown`。
- 授权码绑定客户端与重定向地址：不匹配分别返回 `invalid_grant:client_mismatch` /
  `invalid_grant:redirect_uri_mismatch`。
- 过期返回 `invalid_grant:code_expired`。
- 任何约束不满足即拒绝，**不会静默降级为已授权**。

### 令牌校验与可区分错误

`/userinfo` 的拒绝原因通过 `error` 字段与 `WWW-Authenticate` 头区分：

| 错误码 | 含义 |
|---|---|
| `invalid_token:missing` / `:malformed` | 未携带或格式非法 |
| `invalid_token:signature` | 签名被篡改 |
| `invalid_token:unknown_key` | 签名密钥不在可校验集合（如已被淘汰） |
| `invalid_token:expired` | 已过期（超出时钟偏移容忍） |
| `invalid_token:issuer` | 签发方不符 |
| `invalid_token:revoked` | 已被撤销（含族撤销传播） |
| `insufficient_scope` | 范围不足（HTTP 403） |

### 密钥轮换规则

- 任意时刻仅一个活跃密钥用于签发；`/rotate` 生成新密钥后，旧密钥转入历史集合**仅用于校验**。
- 历史密钥保留窗口 = 访问令牌有效期 + 时钟偏移（`AccessTokenTTL + ClockSkew`），
  保证轮换前已签发且仍有效的令牌继续可校验；超出窗口的密钥在下一次轮换时被清理，
  使用它的令牌以 `invalid_token:unknown_key` 拒绝。
- `/jwks.json` 只暴露当前可用于校验的公钥，与实际校验行为一致；输出按 kid 排序，可复现。

### 刷新令牌轮换与重放检测

- 每次刷新签发新令牌，旧令牌**立即失效**（同一“族” family 标识串联整条轮换链）。
- 已使用的旧令牌再次被出示判定为**重放**：返回 `invalid_grant:refresh_reuse_detected`，
  并撤销整个族的全部刷新令牌与派生访问令牌（失效传播）。
- 族撤销只影响该族，其他会话不受影响。
- 轮换与重放判定在单锁内原子完成：并发刷新同一令牌时**恰好一个成功**，其余被识别为重放。

### 撤销语义

`POST /revoke` 返回可区分的结论：

| `result` | 含义 |
|---|---|
| `revoked` | 撤销成功 |
| `not_found` | 令牌不存在（或非本服务签发） |
| `already_invalid` | 令牌已失效（已用 / 已撤销 / 已过期） |

撤销访问令牌按 `jti` 记录，记录在其过期时刻后自动清理；撤销刷新令牌立即生效。

## 配置项

环境变量覆盖（默认值见 `internal/config`）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `AUTHZ_ISSUER` | `http://localhost:8080` | 令牌签发方（iss） |
| `AUTHZ_ACCESS_TTL` | `10m` | 访问令牌有效期 |
| `AUTHZ_REFRESH_TTL` | `24h` | 刷新令牌有效期 |
| `AUTHZ_CODE_TTL` | `2m` | 授权码有效期 |
| `AUTHZ_CLOCK_SKEW` | `30s` | 校验时钟偏移容忍 |
| `AUTHZ_RATE_LIMIT_PER_MIN` | `120` | 每客户端（或来源 IP）每分钟请求上限，超限返回 429 `rate_limited` |
| `AUTHZ_MAX_CODES` / `AUTHZ_MAX_REFRESH` / `AUTHZ_MAX_REVOKED` | 10000 / 10000 / 100000 | 各存储容量上限 |

资源占用有界：过期条目由后台协程每分钟清理，容量触顶时授权码/刷新令牌写入被拒绝
（`temporarily_unavailable:capacity`），撤销记录按过期时间淘汰最旧的一半。

## 并发一致性

- 授权码消费、刷新令牌轮换、重放判定与族撤销均在互斥锁内原子完成；
- 密钥管理器读写分离（`RWMutex`），轮换与并发校验/签发可安全交错；
- `go test -race ./...` 覆盖并发授权码消费、并发刷新、轮换与签发交错等场景。

## 本地验证

```bash
# 单元 + 端到端测试（含竞态检测）
go test -race ./...

# 手动走一遍完整流程
go run ./cmd/server -addr :8080 &
VERIFIER="local-verifier-0123456789"
CHALLENGE=$(printf '%s' "$VERIFIER" | sha256sum | cut -d' ' -f1 | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
# 1) 授权
curl -s -o /dev/null -w '%{redirect_url}\n' \
  "http://localhost:8080/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:8080/callback&scope=openid%20profile&state=abc&code_challenge=$CHALLENGE&code_challenge_method=S256&user=alice&password=wonderland"
# 2) 用上一步重定向中的 code 换令牌
curl -s -u demo-client:demo-secret -d "grant_type=authorization_code&code=<CODE>&redirect_uri=http://localhost:8080/callback&code_verifier=$VERIFIER" http://localhost:8080/token
# 3) 访问受保护资源
curl -s -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8080/userinfo
# 4) 刷新轮换 / 重放检测 / 撤销 / 密钥轮换
curl -s -u demo-client:demo-secret -d "grant_type=refresh_token&refresh_token=<REFRESH>" http://localhost:8080/token
curl -s -d "token=<TOKEN>" http://localhost:8080/revoke
curl -s -X POST http://localhost:8080/rotate && curl -s http://localhost:8080/jwks.json
```

服务器日志以 `decision=allow|deny|revoke|rotate` 前缀输出每次判定的依据，
例如 `decision=deny endpoint=/token error=invalid_grant:pkce_verification_failed ...`。

## 测试覆盖

- `internal/token`：篡改签名、过期、时钟偏移、签发方不符、未知密钥、畸形令牌；
- `internal/keys`：轮换后历史密钥可校验、淘汰密钥拒绝、JWKS 一致性、并发轮换；
- `internal/store`：授权码单次消费（含并发）、刷新重放族撤销、族间隔离、撤销结论区分、容量有界；
- `internal/server`：非法授权请求矩阵、PKCE 失败即作废、篡改/过期/范围不足令牌、
  密钥轮换期间旧令牌有效与淘汰后拒绝、刷新重放与失效传播、撤销三态、限流 429、
  并发刷新恰好一次成功、轮换与授权并发交错。
