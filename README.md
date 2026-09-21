# oauth2-authz-server-go

一个可本地运行的、仅依赖 Go 标准库的类 OAuth2/OIDC 授权服务器，提供授权码 + PKCE 登录、
令牌签发与本地校验、签名密钥轮换、刷新令牌轮换与重放检测、令牌撤销与失效传播。
所有授权结论均可区分、可解释，并在并发与异常时序下保持一致。

## 快速开始

```bash
go build ./cmd/authz-server
./authz-server -addr :8080   # 预置客户端 demo-client / demo-secret
go test ./... -race         # 运行全部测试（含竞态检测）
```

### 完整流程（curl）

```bash
# 1. 授权码请求（强制 PKCE S256；subject 为本地登录占位）
VERIFIER="my-verifier-0123456789"
CHALLENGE=$(printf %s "$VERIFIER" | sha256sum | cut -d' ' -f1 | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
curl -v "http://localhost:8080/authorize?response_type=code&client_id=demo-client\
&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&scope=read&subject=alice\
&code_challenge=$CHALLENGE&code_challenge_method=S256&state=xyz"
# → 302 重定向到 redirect_uri?code=...&state=xyz

# 2. 授权码换令牌
curl -X POST localhost:8080/token -d grant_type=authorization_code \
  -d client_id=demo-client -d client_secret=demo-secret \
  -d code=<CODE> -d redirect_uri=http://localhost:8080/callback -d code_verifier=$VERIFIER

# 3. 本地校验令牌（可选 required_scope）
curl -X POST localhost:8080/verify -d token=<ACCESS_TOKEN> -d required_scope=read

# 4. 刷新（轮换）
curl -X POST localhost:8080/token -d grant_type=refresh_token \
  -d client_id=demo-client -d client_secret=demo-secret -d refresh_token=<REFRESH_TOKEN>

# 5. 撤销 / 公钥 / 轮换密钥 / 注册客户端
curl -X POST localhost:8080/revoke -d token=<TOKEN>
curl localhost:8080/jwks
curl -X POST localhost:8080/admin/rotate-key
curl -X POST localhost:8080/clients -H 'Content-Type: application/json' \
  -d '{"id":"app2","secret":"pw","redirect_uris":["http://localhost/cb"],"scopes":["read"]}'
```

## 协议语义

| 端点 | 说明 |
|---|---|
| `GET /authorize` | 授权码请求。强制 `response_type=code`、PKCE `S256`、`redirect_uri` 与注册值精确匹配、请求范围为注册范围子集。`subject` 参数为本地登录占位。 |
| `POST /token` | `grant_type=authorization_code`（校验客户端身份、授权码归属、redirect_uri 一致性、PKCE verifier）或 `grant_type=refresh_token`（轮换）。 |
| `POST /verify` | 本地校验访问令牌：签名、有效期（含时钟偏移容忍）、签发方、撤销状态、范围。返回 `{active, reason, claims?}`。 |
| `POST /revoke` | 撤销令牌。自动识别访问令牌（按 jti）与刷新令牌（撤销整个令牌族）。 |
| `GET /jwks` | 公开全部有效与历史公钥（JWK），与实际校验使用同一密钥数据源。 |
| `POST /admin/rotate-key` | 轮换签名密钥（本地演示/测试用）。 |
| `POST /clients` | 注册客户端（本地运行用）。 |

### 可区分的失败结论

- 授权：`unsupported_response_type` / `invalid_client` / `invalid_redirect_uri` / `invalid_scope` / PKCE 缺失或方法不符。
- 授权码消费：`code_not_found` / `code_expired` / `code_already_used`（一次性使用，原子消费）。
- 令牌校验：`malformed_token` / `bad_signature` / `token_expired` / `unknown_key` / `issuer_mismatch` / `token_revoked` / `scope_insufficient`。
- 刷新：`refresh_token_not_found` / `refresh_token_expired` / `refresh_token_replayed` / `family_revoked`。
- 撤销：`revoked` / `token_not_found` / `already_revoked_or_expired`。

任何不满足约束的请求都被明确拒绝并给出上述原因之一，不会静默降级为已授权。
每个请求都会输出判定日志，例如：

```
decision=deny endpoint=verify jti=... client=... reason=scope_insufficient required_scope="write"
decision=deny error=invalid_grant reason=refresh_token_replayed
```

## 密钥轮换规则

- 密钥为 ECDSA P-256（ES256 JWT）。任一时刻只有一把 **active** 密钥用于签发。
- 轮换后旧密钥标记为 retired：**不再用于签发**，但保留在密钥库中用于校验历史令牌，
  因此轮换期间已签发且未过期的令牌继续可校验。
- `/jwks` 公开的密钥集合与校验逻辑使用同一数据源，对外公开信息与实际校验结果一致且可复现。

## 刷新令牌轮换与撤销传播

- 每次刷新都签发新刷新令牌，旧令牌原子地标记为已替换，**立即失效**。
- 旧刷新令牌被再次使用（重放）时：识别为 `refresh_token_replayed`，并**撤销其整个令牌族**；
  该族派生的所有访问令牌（通过令牌中的 `fam` 声明）在校验时一并失效。其他会话（其他族）不受影响。
- 撤销刷新令牌同样撤销整族；撤销访问令牌按 `jti` 记入撤销表直至其过期。
- 所有状态变更在单把互斥锁内原子完成：授权码一次性消费、并发刷新只有一个成功者，
  竞态由 `go test -race` 覆盖验证。

## 配置项

| 命令行参数 | 默认 | 说明 |
|---|---|---|
| `-addr` | `:8080` | 监听地址 |
| `-issuer` | `http://localhost:8080` | 令牌签发方（iss），校验时严格匹配 |
| `-access-ttl` | `15m` | 访问令牌有效期 |
| `-refresh-ttl` | `24h` | 刷新令牌有效期 |
| `-code-ttl` | `5m` | 授权码有效期 |
| `-clock-skew` | `30s` | 校验时的时钟偏移容忍 |
| `-rate-per-second` | `20` | 每客户端每秒请求上限（0 = 不限） |
| `-rate-burst` | `40` | 突发上限；超限返回 `429 rate_limited`（确定性拒绝） |
| `-max-stored-tokens` | `100000` | 授权码 + 刷新令牌存储上限；写入前清理过期项，满则拒绝新签发，资源占用有界 |

## 本地验证方法

```bash
go vet ./...
go test ./... -race -count=1
```

测试覆盖：非法授权请求（重定向不匹配、范围越权、PKCE 缺失）、篡改/过期/签发方不符/未知密钥令牌、
密钥轮换后旧令牌可校验且 JWKS 一致、刷新重放与族撤销、范围越权拒绝、撤销结论可区分、
并发授权码消费与并发刷新（单胜者，`-race` 下无数据竞争）、限流确定性拒绝。
