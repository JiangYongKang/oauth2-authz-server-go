# oauth2-authz-server-go

一个可本地运行的、类 OAuth2/OIDC 的授权服务器，仅依赖 Go 标准库。支持授权码 + PKCE 流程、
RS256 JWT 访问令牌、签名密钥轮换、刷新令牌轮换与重放检测、**会话级撤销**（整次登录一键整体失效，
含并发一致性与失效传播），所有拒绝均返回**可区分的错误码**并输出判定日志。

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
| `/revoke` | POST | 撤销访问或刷新令牌；出示刷新令牌即执行**会话级撤销**（整次登录整体失效）。 |
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

- 每次刷新签发新令牌，旧令牌**立即失效**（同一“族” family 标识串联整条轮换链，
  一次登录授权对应一个 family）。
- 已使用的旧令牌再次被出示判定为**重放**：返回 `invalid_grant:refresh_reuse_detected`，
  并撤销整个族的全部刷新令牌与派生访问令牌（失效传播）。
- 族撤销只影响该族，其他会话不受影响。
- 轮换的全部状态变更（消费旧令牌、写入新刷新令牌、登记新访问令牌 jti）在**单锁内原子提交**
  （`CommitRotation`，JWT 签名在锁外完成）：并发刷新同一令牌时**恰好一个成功**，
  其余被识别为重放；与并发撤销竞争时结论线性确定。

### 撤销语义（含会话级撤销）

`POST /revoke` 根据令牌类型给出两种作用域，并在响应体的 `scope` 字段回显：

| 出示的令牌 | `scope` | 作用范围 |
|---|---|---|
| 刷新令牌（当前的，或轮换链路上仍在有效期内的旧令牌） | `session` | **整次登录会话**：同一次授权链路上已发出的全部访问令牌、已被轮换掉的旧刷新令牌，以及之后任何派生的新刷新/访问令牌，全部立即失效 |
| 访问令牌（JWT） | `token` | 仅该令牌本身（沿用既有语义，不杀会话） |

会话级撤销满足“一次登录被整体失效”：

- 撤销当前刷新令牌后，同会话**轮换前用旧签名密钥签发、但仍在有效期内**的访问令牌
  同样被传播撤销（撤销状态独立于签名密钥，密钥轮换不影响撤销判定）；
- 撤销后即使存在并发换发“抢先”返回了 200，其新访问令牌也已被撤销、新刷新令牌无法再换发；
- 撤销一个会话**只影响该 family**：其它用户、其它客户端、其它登录会话即使共享同一签名密钥也不受影响。

`POST /revoke` 返回可区分的结论（HTTP 200，`result` 字段）：

| `result` | 含义 |
|---|---|
| `revoked` | 会话/令牌此前存活，本次**确实完成**撤销（一次会话只有第一次撤销得到它） |
| `not_found` | 令牌不存在（或非本服务签发） |
| `already_invalid` | 会话此前已被撤销（重复撤销幂等），或出示的刷新令牌已过期 |

容量保护的显式失败（HTTP 503，不静默放行）：

| `error` | 含义 |
|---|---|
| `temporarily_unavailable:revocation_full` | 单令牌撤销记录容量已满且无过期项可回收；服务宁可拒绝也不淘汰仍有效的撤销记录 |
| `temporarily_unavailable:capacity` | 刷新/授权存储容量已满 |

并发一致性结论：撤销与刷新同一时刻发生时，结果**线性确定且可解释**——
二者在同一把互斥锁上排队，要么“先轮换成功、撤销随后覆盖其全部新令牌”，
要么“先撤销、轮换被拒（`invalid_grant:refresh_revoked`）”，
不会出现撤销与新令牌同时成功、撤销后又刷出仍有效后继令牌、或状态半更新。

撤销状态的有界存储（与过期清理、容量限制兼容）：

- 每个被撤销会话只保留一块**墓碑（tombstone）**，`keepUntil` 取该会话所有已知令牌的最晚过期时刻；
  墓碑在此之前不会被任何清理/淘汰移除，因此**仍有效的已撤销令牌不可能因容量淘汰复活**；
- 会话全部令牌过期后，墓碑及其派生索引由后台 Sweep 安全回收（反复撤销不产生多块墓碑）；
- 单访问令牌撤销记录仅在其自身过期后清理；
- 每次判定的依据从日志可见：`decision=revoke endpoint=/revoke scope=session family=... result=revoked`，
  访问令牌被拒时为 `decision=deny ... error=invalid_token:revoked`。

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
（`temporarily_unavailable:capacity`）。撤销记录**不会淘汰仍有效条目**：
单令牌撤销在容量满且无过期项可回收时返回 503 `temporarily_unavailable:revocation_full`；
会话墓碑按“会话内最晚令牌过期时刻”存活，过期后整体回收。

## 并发一致性

- 授权码消费、刷新令牌轮换的**原子提交**（消费旧令牌 + 写入新令牌 + 登记新 jti）、
  重放判定、会话级撤销均在同一把互斥锁内完成；
- 撤销与刷新并发时结论线性确定：不会“撤销与新令牌同时成功”，
  刷新赢家的新令牌最终必被撤销覆盖，或换发直接被 `refresh_revoked` 拒绝；
- 重复撤销幂等：一个会话至多一次状态转移到 `revoked`；
- 密钥管理器读写分离（`RWMutex`），轮换与并发校验/签发可安全交错；
- `go test -race ./...` 覆盖并发授权码消费、并发刷新、撤销/刷新竞争、轮换与签发交错等场景。

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
# 4) 刷新轮换 / 重放检测 / 密钥轮换
curl -s -u demo-client:demo-secret -d "grant_type=refresh_token&refresh_token=<REFRESH>" http://localhost:8080/token
curl -s -X POST http://localhost:8080/rotate && curl -s http://localhost:8080/jwks.json
# 5) 会话级撤销：用（当前或旧的）刷新令牌撤销整次登录，
#    随后同会话访问令牌返回 invalid_token:revoked、任何刷新返回 invalid_grant:refresh_revoked
curl -s -d "token=<REFRESH>" http://localhost:8080/revoke
#   -> {"result":"revoked","scope":"session"}
curl -s -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8080/userinfo   # 401 revoked
curl -s -d "token=<REFRESH>" http://localhost:8080/revoke
#   -> {"result":"already_invalid","scope":"session"}（幂等）
```

服务器日志以 `decision=allow|deny|revoke|rotate` 前缀输出每次判定的依据，
例如 `decision=deny endpoint=/token error=invalid_grant:pkce_verification_failed ...`。

## 测试覆盖

- `internal/token`：篡改签名、过期、时钟偏移、签发方不符、未知密钥、畸形令牌；
- `internal/keys`：轮换后历史密钥可校验、淘汰密钥拒绝、JWKS 一致性、并发轮换；
- `internal/store`：授权码单次消费（含并发）、刷新重放族撤销、族间隔离、撤销结论区分、
  容量有界，以及会话级撤销：
  - 当前刷新令牌撤销后访问令牌/后继刷新/撤销后登记的访问令牌全部失效；
  - 用已轮换的旧刷新令牌撤销后，后继令牌与派生访问令牌全部失效；
  - 撤销三态区分与重复撤销幂等；
  - 撤销与刷新并发（多刷新/多撤销、单刷新/多撤销）结论唯一：会话最终必已死，
    赢家新令牌不可用，至多一次状态转移；
  - 会话隔离（其它 family 不受影响）；
  - 墓碑保护窗口内不被清理、窗口后整体回收；容量满不淘汰有效撤销记录（返回 unavailable）；
  - 50 会话反复轮换+重复撤销时墓碑数量与会话数相等、过期后归零；
- `internal/server`：非法授权请求矩阵、PKCE 失败即作废、篡改/过期/范围不足令牌、
  密钥轮换期间旧令牌有效与淘汰后拒绝、刷新重放与失效传播、撤销三态、限流 429、
  并发刷新恰好一次成功、轮换与授权并发交错，以及会话级撤销端到端：
  - 当前刷新令牌撤销后两张访问令牌与后继刷新均不可用；
  - 旧轮换令牌撤销后后继不可用；
  - 其它会话（共享签名密钥）访问与刷新均不受影响；
  - 撤销与 8 刷新/8 撤销、1 刷新/4 撤销并发时只有一个确定结论；
  - 密钥轮换前签发的同会话访问令牌在撤销后仍被拒；
  - 撤销访问令牌保持单令牌 `scope=token` 语义、会话仍存活（不回归）。
