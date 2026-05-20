# Walkie Talkie Core — 三輪全量代碼 Review 報告

**審查者：** 驚羽 🧠  
**日期：** 2026-04-19  
**分支：** `refactor/wc-to-afr` @ `be36a5d`  
**備份：** `~/Desktop/chorus-code-backup-20260419-2050-pre-review.tar.gz`

---

## 總覽

| 輪次 | 模組 | 文件數 | 行數 | Focus |
|------|------|--------|------|-------|
| R1 | p2p + protocol + crypto | 11 | ~5,045 | 安全優先 |
| R2 | trust + identity + economy | 13 | ~4,712 | 邏輯優先 |
| R3 | resource + gateway + registry + tenant + tui | 15 | ~7,179 | 整合優先 |
| **合計** | | **39** | **~16,936** | |

**嚴重程度分級：**
- 🔴 **Critical** — 安全漏洞或數據一致性問題，合併前必須修復
- 🟡 **Warning** — 邏輯缺陷或設計風險，建議下一迭代修復
- 🟢 **Info** — 已知限制或改進建議

---

## 發現統計

| 嚴重程度 | R1 | R2 | R3 | 合計 |
|----------|----|----|-----|------|
| 🔴 Critical | 1 | 0 | 2 | **3** |
| 🟡 Warning | 3 | 4 | 5 | **12** |
| 🟢 Info | 2 | 3 | 4 | **9** |

---

# R1: p2p + protocol + crypto（安全優先）

## 🔴 CR-1.1: crypto/mod.rs — 解密路徑無重放保護

**文件：** `crypto/mod.rs`  
**嚴重性：** 🔴 Critical

加密層的 nonce 設計為 `salt(4) || counter(8)`，每 session 最多 100,000 條消息。但 **解密側沒有檢查 counter 單調遞增**。攻擊者捕獲一條加密消息後可以無限重放：

```
攻擊場景：
1. A → B: 加密消息 M（counter=42）
2. 攻擊者捕獲密文
3. 攻擊者重放 M → B 接受（counter 42 被再次接受）
4. 結果：重複執行轉賬/任務分配/狀態變更
```

**建議修復：** 在 `Decryptor` 維護 `last_seen_counter: u64`，解密時驗證 `counter > last_seen_counter`，並在驗證後更新。

---

## 🟡 WR-1.1: p2p/handler.rs — DirectResponse 無超時保護

**文件：** `p2p/handler.rs`  
**嚴重性：** 🟡 Warning

request-response 協議的 `send_request` 發出後，如果對端無回應，pending request 將永遠佔用內存。沒有 per-request 超時機制。

**建議：** 在 handler 層加入 `Instant::now()` 記錄發送時間，`on_behaviour_event` 時檢查是否超時（建議 30s），超時則移除並觸發 `DirectEvent::Timeout`。

---

## 🟡 WR-1.2: p2p/network.rs — Gossipsub 消息無簽名驗證

**文件：** `p2p/network.rs`  
**嚴重性：** 🟡 Warning

Gossipsub 接收消息時只解析 `CryptoEnvelope`，未驗證消息來源的 PeerId 是否與發送者一致。惡意節點可以偽造 source PeerId。

**建議：** libp2p Gossipsub 自帶簽名驗證（需在 config 中啟用 `validate()`），或在 `handle_gossipsub_event` 中交叉驗證 message source 與 CryptoEnvelope 中的 sender DID。

---

## 🟡 WR-1.3: crypto/mod.rs — Key Rotation 觸發時機模糊

**文件：** `crypto/mod.rs`  
**嚴重性：** 🟡 Warning

`MAX_MESSAGES_PER_SESSION = 100,000` 是硬編碼上限，但代碼中 counter 達到此值後的行為不明確——是強制終止 session 還是靜默接受？如果靜默接受，nonce 空間耗盡後將重用 nonce，破壞 ChaCha20-Poly1305 的安全性。

**建議：** 在 `encrypt()` 中加入斷言：`assert!(counter < MAX_MESSAGES_PER_SESSION, "session key exhausted, rotate required")`，或在加密前檢查並返回錯誤。

---

## 🟢 IN-1.1: protocol/mod.rs — AgentMessage priority 未用於路由

**文件：** `protocol/mod.rs`  
**嚴重性：** 🟢 Info

`AgentMessage` 有 `priority: u8` 字段，但 P2P 層所有消息平等處理。高優先級任務分配和低優先級心跳使用同一隊列。

**建議：** Phase 3 加入優先級隊列，或在 Gossipsub config 中使用 `message_priority`。

---

## 🟢 IN-1.2: p2p/config.rs — Relay + DCUtR 配置硬編碼

**文件：** `p2p/config.rs`  
**嚴重性：** 🟢 Info

Relay 和 DCUtR 的配置參數全部硬編碼（如 relay max_circuits、dcutr timeout），無法通過配置文件調整。

**建議：** Phase 3 加入 `P2PConfig` 擴展字段或環境變量覆蓋。

---

# R2: trust + identity + economy（邏輯優先）

## 🟡 WR-2.1: trust/peer_binding.rs — NonceStore 驅逐策略不正確

**文件：** `trust/peer_binding.rs`  
**嚴重性：** 🟡 Warning

```rust
self.entries.retain(|_| {
    count += 1;
    count > target
});
```

`HashSet` 無序，`retain` 驅逐的是隨機一半，不是最舊的一半。高頻 nonce（剛插入的）可能被驅逐，而舊 nonce 存活——**削弱重放保護**。

**建議：** 改用 `HashMap<Vec<u8>, u64>`（nonce → timestamp），驅逐時按 timestamp 排序移除最舊的。或使用 `LinkedHashSet` / `IndexMap` 保持插入順序。

---

## 🟡 WR-2.2: trust/types.rs — TrustScore 權重和不為 1.0

**文件：** `trust/types.rs`  
**嚴重性：** 🟡 Warning

```rust
let base = self.identity_score * 0.2
    + self.endorsement_score * 0.5
    + self.guarantor_boost * 0.2;
```

權重和 = 0.2 + 0.5 + 0.2 = **0.9**，不是 1.0。最大 composite = 0.9 × 1.0 × 1.0 = **0.9**，永遠達不到 1.0。

對 TrustLevel 閾值的影響：
- CommunityVerified ≥ 0.8 → 可達（0.9 ≥ 0.8）✓
- 但上限只有 0.9，沒有文檔說明是否故意保留 0.1 給未來組件

**建議：** 如果是故意的，加 comment 說明（如 `// 0.1 reserved for future slashing_score`）。如果不是，調整權重使和為 1.0。

---

## 🟡 WR-2.3: trust/reputation.rs — 用 u8 而非 TrustLevel enum

**文件：** `trust/reputation.rs`  
**嚴重性：** 🟡 Warning

```rust
pub fn identity_component(trust_level_i: u8) -> f64 {
    match trust_level_i {
        0 => 0.0, 1 => 0.5, 2 => 0.7, 3 => 1.0, _ => 0.0,
    }
}
```

用 `u8` 代替 `TrustLevel` enum，失去類型安全。任何 u8 值（如 255）靜默變為 0.0。

**建議：** 改為 `fn identity_component(level: TrustLevel) -> f64`，讓編譯器強制窮舉。

---

## 🟡 WR-2.4: identity/mod.rs — Canonical JSON 簽名可靠性

**文件：** `identity/mod.rs`  
**嚴重性：** 🟡 Warning

`AgentIdentity::sign()` 對 "canonical JSON of all other fields" 簽名。如果 canonicalization 使用 `serde_json::to_string`，默認行為是按 struct 字段定義順序輸出——這在 Rust 中穩定，但跨語言驗證時有風險。

**建議：** 
1. 確認 canonicalization 使用 `serde_json::to_string`（字段順序穩定）
2. 在文檔中明確聲明 canonical form 的確定性要求
3. 長期考慮用 CBOR 或 borsh 替代 JSON 做簽名載荷

---

## 🟢 IN-2.1: trust/slash.rs — 三級懲罰無恢復機制

**文件：** `trust/slash.rs`  
**嚴重性：** 🟢 Info

三級懲罰（First: CRP×0.5, Second: CRP×0.25, Third: 永久斷線）沒有降級/恢復路徑。First strike 後，是否有途徑在 N 天後清除？

**建議：** 為 First/Second strike 加入衰減機制（如 30 天無新違規自動降級），已在 economy_params 設計中考慮但代碼未實現。

---

## 🟢 IN-2.2: economy/afr_ledger.rs — AFR 精度問題

**文件：** `economy/afr_ledger.rs`  
**嚴重性：** 🟢 Info

AFR 餘額用 `f64`，浮點精度可能導致微小差異。如 0.1 + 0.2 ≠ 0.3。

**影響：** 目前 AFR 最小單位 0.01 WC，f64 精度遠超需求。但在跨節點對賬時，浮點誤差可能累積。

**建議：** Phase 3 考慮定點數（如 `i64` 表示 0.001 WC = 1 unit）或 `rust_decimal`。

---

## 🟢 IN-2.3: economy/crp_accumulator.rs — 衰減計算頻率未指定

**文件：** `economy/crp_accumulator.rs`  
**嚴重性：** 🟢 Info

CRP 半衰期 720 小時（30 天），但代碼未說明衰減計算觸發頻率。是每次查詢時計算？還是定期批量計算？不同策略會導致不同結果。

---

# R3: resource + gateway + ratelimit + registry + tenant + tui（整合優先）

## 🔴 CR-3.1: gateway/send_message — 收件人不驗證

**文件：** `gateway/mod.rs`  
**嚴重性：** 🔴 Critical

```rust
pub async fn send_message(...) -> ApiResult {
    // 驗證發送人
    if let Err(e) = state.registry.find_agent(&req.tenant_id, &req.from_agent) {
        return registry_error(e);
    }
    // ❌ 收件人 to_agent 完全不驗證
    // to_agent 可以是空字串、任意字串、不存在的人
```

更嚴重的是 peer 查找邏輯：

```rust
all_peers.into_iter()
    .find(|p| p.to_string() == req.to_agent || req.to_agent.contains(&p.to_string()))
```

`contains` 做**子串匹配**——`to_agent = "12D3KooWAAA"` 會匹配 PeerId 包含 `12D3KooWAAA` 的**任意**節點。

**攻擊場景：**
1. 惡意 agent 發送 `to_agent: "1"` → 匹配第一個 PeerId 包含 "1" 的節點
2. 消息被路由到錯誤的對端
3. 或者 `to_agent: ""` → 不走 P2P，靜默降級為 `queued_local`，消息丟失無告警

**建議修復：**
1. 驗證 `to_agent` 非空且格式合法（did:walkie: 或 PeerId）
2. 移除 `contains`，改為精確匹配
3. 如果收件人不存在，返回 404 而非靜默降級

---

## 🔴 CR-3.2: gateway — 所有端點無認證

**文件：** `gateway/mod.rs`  
**嚴重性：** 🔴 Critical

所有 HTTP API 端點（創建 tenant、註冊 agent、發送消息、刪除 tenant）**沒有任何認證**：
- 無 API key
- 無 JWT
- 無簽名驗證
- 任何人可以創建/刪除 tenant、偽造發送者

**影響：** 在生產部署中，攻擊者可以：
1. 刪除所有 tenant → 全系統癱瘓
2. 偽造 `from_agent` → 冒充任何身份發消息
3. 無限註冊 agent → 資源耗盡

**建議修復：**
1. Phase 2（最小可行）：加入 API key middleware，從 environment variable 讀取
2. Phase 3：每個 request 攜帶 Ed25519 簽名，gateway 驗證
3. Phase 4：基於 DID 的完整身份認證

---

## 🟡 WR-3.1: registry/mod.rs — RwLock poisoning 未處理

**文件：** `registry/mod.rs`  
**嚴重性：** 🟡 Warning

```rust
pub fn create_tenant(&self, ...) -> ... {
    let mut map = self.inner.write().unwrap();  // ← panic on poison
```

所有操作都使用 `.unwrap()`。如果任何持有 lock 的線程 panic，後續所有操作都會 panic → **全系統不可恢復**。

**建議：** 使用 `.unwrap_or_else(|e| e.into_inner())` 恢復 poisoned lock，或返回 `Result`。

---

## 🟡 WR-3.2: resource/engine.rs — Phase 2 信任 Provider 自報數據

**文件：** `resource/engine.rs`  
**嚴重性：** 🟡 Warning

```rust
// In Phase 2, trust the provider's measurement
actual_amount: session.amount,
```

Provider 自己聲明 CPU/memory 使用量，無獨立驗證。惡意 provider 可以虛報 10x 用量騙取 CRP。

**已知限制，但需關注：** Endorsement 系統（trust/endorsement.rs）在 Phase 4 會交叉驗證 consumer 端測量。但從 Phase 2 到 Phase 4 的過渡期，此漏洞可用。

**建議：** 至少加入 sanity check：`actual_amount` 不能超過 `declared_amount` 的某個倍數（如 2x）。

---

## 🟡 WR-3.3: resource/engine.rs — StorageProof 驗證邏輯有漏洞

**文件：** `resource/engine.rs`  
**嚴重性：** 🟡 Warning

```rust
pub fn verify_storage_proof(&mut self, proof: &StorageProof, expected_hmac: &[u8]) -> bool {
    if proof.hmac != expected_hmac { ... }
}
```

`expected_hmac` 由調用者傳入。但問題是：**調用者（consumer）怎麼知道 expected_hmac？**

如果 consumer 已經知道數據內容才能計算 HMAC，那 PoR-lite 挑戰毫無意義——consumer 已經知道答案。

**建議：** HMAC key 應該是 session 建立時協商的共享密鑰。consumer 只驗證 HMAC 格式正確（用共享密鑰驗證），不需要知道數據內容。或者改用 commitment scheme：provider 先 commit hash，後 reveal。

---

## 🟡 WR-3.4: resource/match_engine.rs — trust_bonus/crp_multiplier 未注入

**文件：** `resource/match_engine.rs`  
**嚴重性：** 🟡 Warning

```rust
let components = ScoreComponents {
    resource: Self::resource_score(&ad, req, remaining_cpu, remaining_mem),
    latency: self.latency.score(&ad.agent_id),
    reliability: self.reliability.score(&ad.agent_id),
    trust_bonus: 0.0,   // populated by caller using TrustScore
    crp_multiplier: 1.0, // populated by caller using TrustScore
};
```

`trust_bonus` 和 `crp_multiplier` 始終為默認值（0.0 和 1.0），**信任等級對匹配完全無影響**。注釋說 "populated by caller" 但沒有任何 caller 這樣做。

**影響：** CommunityVerified 節點和 Unverified 節點在資源匹配中獲得相同排序。

**建議：** `find_providers` 應接受 `trust_scores: HashMap<String, TrustScore>` 參數，在計算分數時注入。

---

## 🟡 WR-3.5: resource/proof.rs — proof_hash 用字符串拼接

**文件：** `resource/proof.rs`  
**嚴重性：** 🟡 Warning

```rust
let data = format!("{}:{}:{}:{}:{}:{}:{}",
    self.consumer, self.provider, self.session_id,
    self.cpu_used_ms, self.memory_peak_bytes,
    self.window_start, self.window_end,
);
blake3::hash(data.as_bytes())
```

分隔符 `:` 存在歧義風險：
- `session_id = "a:b"` + `cpu_used_ms = 100` → `"a:b:100:..."`
- `session_id = "a"` + `cpu_used_ms` 被解析為 `"b:100"` → 相同 hash

DID 和 base64url 不含 `:`，所以 consumer/provider 安全。但 `session_id` 由 `ResourceSessionManager` 生成（UUID 格式，含 `-`），目前安全。

**建議：** 改用長度前綴編碼（如 `len|data|len|data|...`）或直接序列化 struct 為 bytes，消除歧義。

---

## 🟢 IN-3.1: gateway — 版本號硬編碼

**文件：** `gateway/mod.rs`  
**嚴重性：** 🟢 Info

```rust
pub async fn health() -> ApiResult {
    ok_json(serde_json::json!({ "status": "healthy", "version": "0.2.0" }))
}
```

版本號 `"0.2.0"` 硬編碼，與 Cargo.toml 和 agent version 不同步風險。

**建議：** 用 `env!("CARGO_PKG_VERSION")` 或 `clap::crate_version!()` 自動同步。

---

## 🟢 IN-3.2: registry — 每次 read 克隆完整 Tenant

**文件：** `registry/mod.rs`  
**嚴重性：** 🟢 Info

```rust
pub fn get_tenant(&self, tenant_id: &str) -> Option<Tenant> {
    self.inner.read().unwrap().get(tenant_id).cloned()
}
```

每次讀取克隆整個 Tenant（含所有 AgentIdentity）。10 個 agent × 1KB/agent = 10KB，暫時可接受。但 100+ agent 的 tenant 在高頻查詢下會成為瓶頸。

**建議：** Phase 3 考慮 `Arc<Tenant>` 或 read guard 返回引用。

---

## 🟢 IN-3.3: tenant/mod.rs — 無審計日誌

**文件：** `tenant/mod.rs`  
**嚴重性：** 🟢 Info

Tenant/Agent 的創建、刪除、配置變更無審計日誌。生產環境中無法追蹤誰在何時做了什麼。

**建議：** Phase 3 加入 `AuditLog` trait，記錄所有寫操作。

---

## 🟢 IN-3.4: resource/backoff.rs — 退避策略簡單但足夠

**文件：** `resource/backoff.rs`  
**嚴重性：** 🟢 Info

指數退避 + jitter，max level 5（最大 32s）。對 Phase 2 足夠，但 Phase 3 可能需要根據網絡規模調整上限。

---

# 架構級觀察

## ✅ 設計優點

1. **分層清晰** — crypto/trust/economy/resource/gateway 各層職責明確，耦合度低
2. **經濟參數 frozen v1.1** — 20 個常量集中管理，文檔完整，測試充分（`economy_params.rs` 是全項目質量最高的文件）
3. **E2EE 架構合理** — X25519 DH + ChaCha20-Poly1305，nonce 分層（salt + counter）
4. **信任層遞進設計** — Unverified → Cryptographic → Guaranteed → CommunityVerified，邏輯嚴密
5. **三級懲罰制度** — 有明確的遞進邏輯和可配置參數
6. **測試覆蓋率** — 每個模組都有單元測試，邊界條件覆蓋較好

## ⚠️ 架構風險

1. **Gateway 是全鏈條最弱環節** — 無認證、無輸入驗證、收件人邏輯有漏洞。建議在合併前至少完成 CR-3.1 和 CR-3.2 的最小修復
2. **信任層未與資源匹配打通** — trust_bonus/crp_multiplier 在 match_engine 中為空，信任層做了計算但不影響決策
3. **Crypto 層重放問題** — CR-1.1 是真正的安全漏洞，影響所有加密通信

---

# 修復優先級建議

## 必須在合併前修復（P0）

| ID | 文件 | 工作量 | 說明 |
|----|------|--------|------|
| CR-1.1 | crypto/mod.rs | S | 加入 counter 單調遞增檢查 |
| CR-3.1 | gateway/mod.rs | S | 收件人驗證 + 移除 contains |
| CR-3.2 | gateway/mod.rs | M | 最小 API key middleware |

**工作量估計：** S=1-2h, M=3-5h, L=1-2 天

## 下一迭代修復（P1）

| ID | 文件 | 工作量 |
|----|------|--------|
| WR-1.1 | p2p/handler.rs | M |
| WR-1.2 | p2p/network.rs | M |
| WR-1.3 | crypto/mod.rs | S |
| WR-2.1 | trust/peer_binding.rs | S |
| WR-2.2 | trust/types.rs | S |
| WR-2.3 | trust/reputation.rs | S |
| WR-2.4 | identity/mod.rs | S |
| WR-3.1 | registry/mod.rs | S |
| WR-3.2 | resource/engine.rs | L |
| WR-3.3 | resource/engine.rs | M |
| WR-3.4 | resource/match_engine.rs | M |
| WR-3.5 | resource/proof.rs | S |

## 記錄但暫不修復（P2）

IN-1.1, IN-1.2, IN-2.1, IN-2.2, IN-2.3, IN-3.1, IN-3.2, IN-3.3, IN-3.4

---

*驚羽 🧠 — 2026-04-19 21:30 SGT*
