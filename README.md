# oauth2-authz-server-go

一个可本地运行的、类 OAuth2/OIDC 的授权服务器，仅依赖 Go 标准库。支持授权码 + PKCE 流程、
RS256 JWT 访问令牌、签名密钥轮换、刷新令牌轮换与重放检测、**会话级（授权链）撤销**与
令牌撤销及失效传播，所有拒绝均返回**可区分的错误码**并输出判定日志。

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
| `/revoke` | POST | 撤销访问令牌（单令牌）或刷新令牌（会话级：终止整条授权链）。 |
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
  即一次登录会话）。
- 轮换是**原子**的：旧令牌消费与后继令牌入存在存储层同一临界区完成，
  会话级撤销无法插入两步之间，因此不会产生“撤销成功后仍刷新出有效后继”。
- 已使用的旧令牌再次被出示判定为**重放**：返回 `invalid_grant:refresh_reuse_detected`，
  并在会话仍存活时终止整个会话（族）的全部刷新令牌与派生访问令牌（失效传播）。
  **重放判定无条件优先**：无论会话是否已经结束（例如先被显式撤销）、是否在并发出示，
  已用过的令牌再次出现都给出同一个重放结论，不会改判为 `refresh_revoked`。
- 会话终止只影响该族，其他会话不受影响。
- 并发刷新同一令牌时**恰好一个成功，其余失败方结论一致且确定**：全部判定为重放
  `invalid_grant:refresh_reuse_detected`（首个重放者负责终止整族），不会出现一部分
  报重放、另一部分报已撤销的混合结果。
- 过期未消费的刷新令牌换发返回 `invalid_grant:refresh_expired`；已终止会话中
  未用过的令牌换发返回 `invalid_grant:refresh_revoked`。

### 撤销语义

`POST /revoke` 对刷新令牌执行**会话级撤销**（终止整条授权链/令牌族 family），
对访问令牌执行按 `jti` 的单令牌撤销。结论可区分：

| `result` | 刷新令牌（会话级） | 访问令牌（单令牌） |
|---|---|---|
| `revoked` | 该会话此前存活，本次调用完成终止 | 令牌此前有效，本次撤销生效 |
| `not_found` | 令牌不存在（或非本服务签发、已被过期清理） | 同左 |
| `already_invalid` | 会话此前已终止（重复撤销、重放之后），或被点名令牌自身早已失效（已过期、未轮换却已被逐条撤销），幂等 | 令牌已撤销或已过期，幂等 |

对刷新令牌的判定口径（恢复的历史语义）：

- 出示**当前刷新令牌**、或**已被轮换掉但仍在有效期内**的旧令牌，且会话仍存活：
  撤销真实发生，返回 `revoked`，整条授权链（含轮换后继与其派生访问令牌）立即终止；
- 出示**早已过期**的刷新令牌（无论它是否被轮换消费过——把刷新令牌有效期设得比访问
  令牌短，例如几秒，即可复现“刷新令牌已失效、同次登录的访问令牌仍有效”）：它**本来
  就是无效的**，返回 `already_invalid`，**不算一次真实的会话撤销**，也**不连累同一次
  登录中仍在有效期内的访问令牌**；
- 出示未被轮换消费但已被逐条撤销的刷新令牌：同样返回 `already_invalid`，不级联到会话；
- 重复撤销保持幂等；`revoked` / `not_found` / `already_invalid` 三类结论始终可区分。

> 注意区分两个端点的口径：`/revoke` 对“已过期/已逐条撤销”的刷新令牌只记 `already_invalid`
> 而不动会话；`/token`（换发）对“已被轮换消费”的令牌则一律判重放，两者互不影响。

会话级撤销一次终止同一次授权链路上的全部凭据：

- 当前及族内所有刷新令牌立即失效，之后**不会再产生任何有效后继刷新令牌**；
- 已轮换掉的旧刷新令牌与后继令牌的关系作废，旧令牌重放与正常换发都被拒绝；
- 同会话已签发的访问令牌（含密钥轮换前签发、仍在有效期内者）在校验时被拒绝，
  返回 `invalid_token:revoked`；撤销之后才签发/登记的派生访问令牌同样被拒绝；
- 终止严格按族隔离：其它用户、其它客户端、其它登录会话不受影响，即使共享签名密钥。

并发的撤销与刷新在存储层单临界区内线性化，只可能得到两种可解释结论：

1. **撤销先于刷新**：刷新返回 `invalid_grant:refresh_revoked`，后继令牌绝不入存；
2. **刷新先于撤销**：刷新成功一次，但撤销随后终止整条链，新刷新令牌与新访问令牌
   立即失效。不会出现“撤销与新令牌同时成功且后继仍有效”或状态半更新。

访问令牌的逐条撤销记录在其过期时刻后自动清理；刷新令牌撤销立即生效。
会话终止标记保留到族内最后一个可能仍有效的令牌过期为止，随后由清理协程回收。

### 撤销记录容量与失败关闭

逐条访问令牌撤销记录受 `AUTHZ_MAX_REVOKED` 上限约束。容量触顶时先清理过期记录，
仍满则撤销请求失败关闭（HTTP 503 `temporarily_unavailable:revocation_capacity`），
**绝不淘汰仍有效的撤销记录而让令牌复活**，也不会静默放行。

会话级撤销不依赖逐条撤销记录：族终止标记 + `jti → family` 反向索引是访问令牌
失效的最终判定依据，因此即使逐条记录容量已满，会话撤销仍然有效且不会被容量淘汰复活。

### 过期 / 已失效令牌与清理、容量、密钥轮换的兼容范围

- **过期优先，不误伤**：`/revoke` 对已过期刷新令牌一律返回 `already_invalid` 且不写
  任何终止标记，因此该结论不会被过期清理或容量状态影响——令牌被清理前出示是
  `already_invalid`，被清理后出示是 `not_found`，两种情况下同会话仍有效的访问令牌都
  不受连累。
- **清理不复活**：过期条目（授权码、刷新令牌、逐条访问令牌撤销记录）由后台协程定期
  清理；会话终止标记保留到族内最后一个可能仍有效的令牌（刷新/访问）过期为止。仍有
  有效令牌牵挂的族标记绝不提前回收，因此“撤销之后新产生的令牌仍失效”不会因清理而复活。
- **容量不复活**：逐条撤销记录触顶时失败关闭（503），不淘汰仍有效记录；会话级撤销走
  族标记通道，不占逐条容量，容量压力下依然完整生效。
- **密钥轮换透明**：族标记按 `jti → family` 判定，与 JWT 用哪一代签名密钥无关；
  轮换前签发、仍在有效期内的同会话访问令牌，在密钥轮换后仍会以 `invalid_token:revoked`
  被拒绝（而不是 `unknown_key`）。
- **隔离不扩散**：以上判定严格按族生效，不同用户、客户端、登录会话即使共享签名密钥
  也互不影响。


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
（`temporarily_unavailable:capacity`），逐条访问令牌撤销记录触顶时撤销请求失败关闭
（`temporarily_unavailable:revocation_capacity`），而**不会淘汰仍有效的撤销记录**。
会话终止标记在族内最后一个令牌过期后才回收，仍有效令牌牵挂的标记绝不提前清理。

## 并发一致性

- 授权码消费、刷新令牌**原子轮换**（消费旧令牌 + 后继入存）、重放判定、
  会话级撤销与访问令牌失效判定均在互斥锁内原子完成；撤销与刷新并发只可能
  线性化为“撤销先”或“刷新先”两种可解释结论，终态都是整个会话终止；
- 密钥管理器读写分离（`RWMutex`），轮换与并发校验/签发可安全交错；
- `go test -race ./...` 覆盖并发授权码消费、并发刷新、撤销与刷新竞争、
  轮换与签发交错等场景。

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

# 5) 会话级撤销：用刷新令牌终止整条授权链
#    先拿到 access/refresh，再撤销 refresh（scope=session），
#    然后观察：同会话 access 401 invalid_token:revoked、再次刷新 400 refresh_revoked。
curl -s -d "token=<REFRESH>" http://localhost:8080/revoke     # -> {"result":"revoked"}
curl -s -d "token=<REFRESH>" http://localhost:8080/revoke     # -> {"result":"already_invalid"}
curl -s -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8080/userinfo
#    日志包含判定依据：decision=revoke scope=session family=<ID> result=revoked

# 6) 回归复现一：用已过期刷新令牌撤销，不连累仍有效的访问令牌
#    用秒级刷新 TTL 启动：AUTHZ_REFRESH_TTL=5s go run ./cmd/server -addr :8080
#    完整走一遍授权拿 access/refresh，等 6 秒后：
curl -s -d "token=<EXPIRED_REFRESH>" http://localhost:8080/revoke
#    -> {"result":"already_invalid"}   （本来就无效，不是 revoked）
curl -s -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8080/userinfo   # 仍 200

# 7) 回归复现二：会话终止后再出示已用过的旧刷新令牌，结论仍是重放
#    先 refresh 一次拿到 RT2，再 curl -d "token=<RT2>" /revoke 终止会话，然后重复出示 RT1：
curl -s -u demo-client:demo-secret -d "grant_type=refresh_token&refresh_token=<RT1>" http://localhost:8080/token
#    -> 400 invalid_grant:refresh_reuse_detected（无论撤没撤销会话，结论不变）

# 8) 回归复现三：并发用同一刷新令牌换令牌，恰好一个成功，其余结论一致
for i in $(seq 1 8); do
  curl -s -u demo-client:demo-secret -d "grant_type=refresh_token&refresh_token=<RT>" \
    http://localhost:8080/token &
done; wait
#    -> 恰好一个 200，其余全部 400 invalid_grant:refresh_reuse_detected（不夹杂 refresh_revoked）
```

服务器日志以 `decision=allow|deny|revoke|rotate` 前缀输出每次判定的依据，
例如 `decision=deny endpoint=/token error=invalid_grant:pkce_verification_failed ...`。

## 测试覆盖

- `internal/token`：篡改签名、过期、时钟偏移、签发方不符、未知密钥、畸形令牌；
- `internal/keys`：轮换后历史密钥可校验、淘汰密钥拒绝、JWKS 一致性、并发轮换；
- `internal/store`：授权码单次消费（含并发）、刷新重放族撤销、族间隔离、撤销结论区分、
  会话级撤销（当前/仍有效已轮换旧令牌撤销后访问令牌与后继刷新全失效、幂等三态、撤销后登记的
  令牌仍拒绝、撤销与刷新并发两种线性化顺序、容量失败关闭不复活、终止标记到期回收）、
  本次回归（过期/已逐条撤销/已轮换且已过期的刷新令牌撤销返回 already_invalid 且不连累
  同会话有效访问令牌、会话终止后重放结论不变、并发轮换失败方全部一致为重放、
  重放终止的会话级效果与族隔离不削弱）；
- `internal/server`：非法授权请求矩阵、PKCE 失败即作废、篡改/过期/范围不足令牌、
  密钥轮换期间旧令牌有效与淘汰后拒绝、刷新重放与失效传播、撤销三态、限流 429、
  并发刷新恰好一次成功且失败方结论一致、撤销与刷新并发结论一致、撤销跨密钥轮换传播、撤销容量 503、
  轮换与授权并发交错，以及本次三个端到端回归（秒级刷新 TTL 下撤销过期刷新不波及有效访问令牌、
  会话终止后重放结论保持重放、并发刷新失败方结论统一）。

> 测试日志可看出业务覆盖与每条用例结果：
> `go test -race -v ./...` 中 `=== RUN`/`--- PASS` 按“授权码 / PKCE / JWT 校验 /
> 密钥轮换 / 刷新轮换与重放 / 会话级撤销 / 过期与已失效令牌 / 容量与过期清理 / 限流”
> 等业务分组命名；并发用例还会输出线性化顺序覆盖（race order coverage）。
> 想看业务总览可运行 `go test -race -v ./... 2>&1 | grep -E '=== RUN|--- PASS|--- FAIL'`。
