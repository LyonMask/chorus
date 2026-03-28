# v4 平台化架構 — 交付報告

**時間:** 2026-03-28 09:31 CST
**任務:** 在現有 47/47 tests 基礎上添加 Tenant / Registry / RateLimiter / API Gateway
**結果:** ✅ 94/94 tests pass（47 original + 47 new）

---

## 新增模組

### 1. `tenant/` — 租戶管理（9 tests）
- `TenantConfig`: 可配置 max_agents、allowed_capabilities、rate_limit、require_approval
- `Tenant`: 租戶實體，管理 agents 列表
- `register_agent()`: 注冊時檢查 max_agents 上限、capability 白名單、重複、活躍狀態
- `deregister_agent()`: 按 agent_id 移除
- `TenantSummary`: 輕量 API 響應類型

### 2. `registry/` — Agent 註冊中心（12 tests）
- `AgentRegistry`: `Arc<RwLock<HashMap>>` 線程安全
- Tenant CRUD: create / get / list / remove / has
- Agent 管理: register / deregister / list / find / tenant_has_agent
- 錯誤類型: TenantNotFound / AgentNotFound / TenantExists / Tenant error

### 3. `ratelimit/` — 令牌桶限流器（11 tests）
- `Bucket`: tokens / max_tokens / rate / last_refill，fractional 精度
- `RateLimiter`: 按 `tenant_id:agent_id` 鍵控
- `try_acquire()`: 自動 refill → 消耗
- `set_rate()` / `set_tenant_rate()`: 動態調整
- `available_tokens()` / `reset()` / `bucket_count()`

### 4. `gateway/` — HTTP API 網關（15 tests）
| 端點 | 方法 | 功能 |
|------|------|------|
| `/health` | GET | 健康檢查 |
| `/tenants` | POST | 創建租戶 |
| `/tenants` | GET | 列出租戶 |
| `/tenants/{id}` | GET | 查詢租戶 |
| `/tenants/{id}/agents` | POST | 注冊 Agent |
| `/tenants/{id}/agents` | GET | 列出 Agent |
| `/tenants/{id}/agents/{aid}` | DELETE | 注銷 Agent |
| `/messages` | POST | 發送消息（限流） |

- 統一 `ApiResult = (StatusCode, Json<Value>)` 響應
- 錯誤映射: RegistryError → HTTP 404/409/400
- 限流: 429 Too Many Requests
- 測試策略: 直接調用 handler 函數（非 oneshot），確保 Arc 狀態共享正確

---

## 架構圖

```
                    ┌──────────────┐
                    │  API Gateway  │  axum HTTP
                    │  /health      │
                    │  /tenants     │
                    │  /messages    │
                    └──────┬───────┘
                           │ State(AppState)
                    ┌──────┴───────┐
                    │  AgentRegistry │  Arc<RwLock<HashMap>>
                    │  Tenant CRUD   │
                    │  Agent CRUD    │
                    └──────┬───────┘
                           │
                    ┌──────┴───────┐
                    │  Tenant       │
                    │  agents[]     │  → AgentIdentity
                    │  config       │  → TenantConfig
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        RateLimiter   identity     protocol
        (token bucket) (DID+sig)   (walkie-talkie)
```

---

## 測試明細

```
94 passed; 0 failed

原有 47:
  crypto          6 tests
  identity       14 tests
  p2p             2 tests
  protocol       25 tests

新增 47:
  tenant          9 tests
  registry       12 tests
  ratelimit      11 tests
  gateway        15 tests
```

---

## 技術決策

| 決策 | 選擇 | 理由 |
|------|------|------|
| 並發 | `Arc<RwLock<HashMap>>` | 讀多寫少，RwLock 比 Mutex 更好 |
| 限流算法 | Token Bucket | 允許 burst，實現簡單 |
| API 測試 | 直接調用 handler | 避免 axum oneshot 狀態共享問題 |
| 錯誤處理 | thiserror + 統一映射 | RegistryError → HTTP status code |
| TenantSummary | 複用 tenant 模組類型 | registry `pub use` re-export |

---

## 依賴變更

**新增:** `axum = "0.7"`
**移除:** `tower`, `tower-http`, `urlencoding`（不需要）

---

*交付人: Rustacean 🦀🔐*
