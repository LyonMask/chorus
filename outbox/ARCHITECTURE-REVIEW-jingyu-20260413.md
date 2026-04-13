# 🔍 架構審查報告 — Walkie Talkie v0.3.0

**審查人：** 驚羽 🧠
**日期：** 2026-04-13 08:57 SGT
**基線：** 264 tests, 15,383 行, Phase 2B+3 完成
**範圍：** crypto / p2p / resource / identity / protocol

---

## 總評

Phase 2B+3 功能開發完成度高。模組劃分清晰，E2EE 實現紮實，測試覆蓋良好。以下問題按優先級分級，P0 標記 🔴 的必須在 Heimdall 安全審計前修復或至少文檔化。

---

## 🔴 P0 — 安全關鍵（Heimdall 必看）

### S1. proof_hash() 使用 DefaultHasher — 跨平台不可確定

**文件：** `resource/proof.rs` WorkReceipt::proof_hash()

**問題：** `std::collections::hash_map::DefaultHasher` 在不同 Rust 版本和平台上可能產生不同哈希。不同節點對相同 receipt 算出的 proof_hash 可能不一致。

```rust
// 現狀 — 不可移植
use std::collections::hash_map::DefaultHasher;
let mut hasher = DefaultHasher::new();
data.hash(&mut hasher);
format!("{:016x}", hasher.finish())
```

**影響：** contribution ledger 中的 proof_hash 在不同節點間不可驗證。如果將來需要跨節點審計或receipt比對，會失敗。

**修復：** 替換為 blake3 或 sha2。代碼已有 `blake3` 的 comment placeholder，現在就該做——在生成任何 real receipt 之前。

**工作量：** 30min

---

### S2. ResourceAdvertisement 簽名未驗證

**文件：** `resource/types.rs`

**問題：** `signable_bytes()` 和 `validate()` 存在，但簽名從未被生成或驗證。所有節點的 `signature` 字段都是空 Vec。ResourceAdvertisement 的驗證僅依賴結構完整性（字段範圍、時間戳），不驗證身份。

```rust
// 到處都是這樣創建的：
ResourceAdvertisement { ..., signature: Vec::new() }
```

**影響：** 任何節點都可以偽造任意 agent_id 的資源聲明。惡意節點可以冒充高貢獻節點搶占資源匹配。

**修復：**
1. 在 identity 模組中生成 Ed25519 簽名
2. 在 `handle_resource_declaration()` 中驗證簽名
3. 拒絕無簽名或簽名無效的聲明

**工作量：** 1-2h

---

### S3. libp2p PeerId 與 Agent DID 無密碼學綁定

**文件：** `p2p/network.rs` + `identity/mod.rs`

**問題：** libp2p 使用 X25519 keypair（Noise 協議），Agent Identity 使用 Ed25519 keypair。兩套獨立的密鑰體系，無法證明「這個 libp2p PeerId 控制這個 did:walkie 身份」。

**攻擊場景：**
1. Eve 創建一個新的 libp2p 節點
2. Eve 聲稱自己是 `did:walkie:steve-jobs`（複製 Steve 的 public_key）
3. 因為 ResourceDeclaration 沒有綁定 PeerId（S2），Eve 可以注入虛假資源聲明

**修復方案（Phase 3 選項）：**
- **方案 A（簡單）：** 在 KeyExchange 時附帶 Ed25519 signature over libp2p public key
- **方案 B（完整）：** 採用 libp2p 的 `signed_peer_record` 機制綁定身份

**工作量：** 方案 A 2h / 方案 B 4h

---

### S4. Nonce 構造：前 4 字節永遠為零

**文件：** `crypto/mod.rs` SessionKey::encrypt()

```rust
let mut nonce_bytes = [0u8; NONCE_SIZE]; // 12 bytes, all zeros
nonce_bytes[4..].copy_from_slice(&self.counter.to_le_bytes()); // only last 8 bytes
```

**問題：** 12 字節 nonce 中只有後 8 字節是 counter，前 4 字節永遠為零。雖然 2^64 的 counter 空間對單 session 足夠（限 100,000 條消息），但這是一個非標準的 nonce 使用模式。

**風險：** 如果兩個 session 意外使用了相同的 shared_secret（例如 DH 重放），nonce 會從相同起點開始。如果第一條消息的 nonce 都是 `[0,0,0,0,0,0,0,0,0,0,0,0]`，可能導致 nonce 重用。

**修復：** 前 4 字節使用 session 隨機 salt（在 create_session 時生成）。

```rust
pub struct SessionKey {
    cipher: ChaCha20Poly1305,
    counter: u64,
    created_at: Instant,
    salt: [u8; 4], // <-- 新增
}
```

**工作量：** 30min

---

### S5. WorkReceipt 簽名字段永遠為空

**文件：** `resource/proof.rs` WorkReceipt

**問題：** `provider_signature` 字段存在但從未填充。`release_and_prove()` 創建 receipt 但不簽名。`record_consumption()` 不驗證簽名。

**影響：** 貢獻追蹤完全基於信任（代碼註釋已承認："In Phase 2, trust the provider's measurement"）。對 Phase 3 信任層是阻礙。

**建議：** Phase 4 路線圖必須包含 receipt 簽名。現在至少在 WorkReceipt 上加一個 `is_signed()` 檢查，未簽名的 receipt 記錄為 `unverified` 類別。

**工作量：** 30min（加標記）/ 2h（實現簽名）

---

## 🟡 P1 — 架構問題

### A1. ContributionEngine 所有字段都是 pub

**文件：** `resource/engine.rs`

**問題：** 外部代碼可以直接修改 `ledger`、`table`、`sessions` 等內部狀態，繞過所有業務邏輯。

**修復：** 改為 `pub(crate)` 或提供 getter 方法。

**工作量：** 15min

---

### A2. MatchEngine 沒有時間衰減

**問題：** 資源廣告收到後直到 TTL 過期前，匹配分數不隨時間衰減。一個 5 分鐘前的廣告和新廣告權重相同。

**建議：** 在 `resource_score()` 中加入 `age_factor`：

```rust
let age_ms = now_ms().saturating_sub(ad.timestamp);
let age_factor = if age_ms < 60_000 { 1.0 } else { (1.0 - age_ms as f64 / 300_000.0).max(0.1) };
// score *= age_factor
```

**工作量：** 30min

---

### A3. Session 管理器 allocation 追蹤不完整

**文件：** `resource/session.rs`

**問題：** `allocations` HashMap 的 entry 是 `(f32, u64, u64, u64)`（cpu, mem, bw, storage），但 `create_session` 只累加 cpu 和 mem（entry.0, entry.1）。bw 和 storage（entry.2, entry.3）永遠為零，且在 release/revoke 時也只減 cpu 和 mem。

```rust
// create_session 只設了 entry.0 和 entry.1
let entry = self.allocations.entry(provider).or_insert((0.0, 0, 0, 0));
entry.0 += cpu;
entry.1 += memory_mb;
// entry.2 (bw) 和 entry.3 (storage) 從未被使用
```

**影響：** 如果未來添加 bandwidth/storage 的資源分配，現有邏輯會出錯。也是 dead code。

**修復：** 要麼移除 bw/storage 追蹤（簡化為 `(f32, u64)` tuple），要麼在 create_session/release 中完整實現。

**工作量：** 30min

---

### A4. request_resource() API 設計反直覺

**文件：** `p2p/network.rs` P2PCommand::RequestResource

**問題：** `request_resource()` 在成功發送請求後返回 `Err("wait for ResourceOfferReceived event")`。這是 fire-and-forget + event poll 模式，對調用者不友好。

```rust
// 當前行為：
let result = net.request_resource(peer, request).await;
// 成功發送 → Err("wait for event")
// 失敗（離線）→ Err("queued for reconnect")
```

**建議：** 改為返回 `Result<()>` 表示是否已發送，文檔中明確說明需要監聽 `ResourceOfferReceived` 事件。或者提供一個 `request_resource_with_callback()` 返回 oneshot channel。

**工作量：** 1h

---

### A5. BroadcastStructured 對 Gossipsub 濫用

**文件：** `p2p/network.rs` P2PCommand::BroadcastStructured

**問題：** 為每個有 E2EE session 的 peer 獨立發布一條 Gossipsub 消息。N 個 peer = N 條 Gossipsub publish。每條消息只有一個 peer 能解密，其餘 peer 收到後解密失敗靜默丟棄。

**影響：** 在 100 節點網絡中，一次「廣播」產生 100 條 Gossipsub 消息。每個節點收到 100 條（來自所有其他節點的加密副本），其中 99 條解密失敗。消息放大因子 = O(N²)。

**修復：** BroadcastStructured 應改用 Direct channel 逐個發送（已有的 send_encrypted），而不是 Gossipsub。或者使用真正的 group key（Phase 4）。

**工作量：** 2h

---

### A6. handle_resource_accept 匹配邏輯錯誤風險

**文件：** `p2p/handler.rs` handle_resource_accept()

**問題：** 找 pending session 是按 `consumer == from.to_string()` 匹配，不是按 session_id。如果一個 provider 對同一個 consumer 有多個 pending sessions（連續發送了多個 offer），會選擇第一個找到的——可能是錯的 session。

```rust
for session in pending {
    if session.consumer == from.to_string() {
        found_sid = session.session_id.clone();
        break; // 取第一個，不一定對
    }
}
```

**修復：** ResourceAccept 應該帶 session_id，按 session_id 精確匹配。

**工作量：** 30min

---

## 🟢 P2 — 代碼質量 / 次要

### C1. ContributionLedger 無限增長

`provided` 和 `consumed` Vec 永遠增長，沒有修剪或分頁機制。長時間運行的節點會 OOM。

**建議：** 加 `MAX_RECORDS` 上限（如 10,000），超出時淘汰最舊的記錄。

---

### C2. economy_params.rs 定義了 30+ 常量但幾乎未被使用

CRP/WC 經濟模型參數在 `economy_params.rs` 中定義得很完整，但資源匹配、評分、貢獻追蹤的實際代碼中**沒有引用任何一個經濟參數**。經濟模型目前是一個獨立的文檔，不是可執行的邏輯。

**建議：** Phase 4 路線圖應包含「經濟參數落地」，將 CRP/WC 計算整合到 ContributionEngine 中。

---

### C3. 2 個 Clippy warnings

```
warning: `walkie-talkie-core` (lib test) generated 2 warnings
```

修復即可。

---

### C4. Session ID 泄露身份

`generate_session_id()` 格式為 `{consumer}_{provider}_{now}_{random}`。consumer 和 provider 的 DID 明文暴露在 session_id 中。

**風險：** 低。但如果有 packet capture，可以知道哪些 agent 之間建立了資源 session。

**建議：** 使用隨機 UUID，DID 只存在 session 結構體內。

---

## 📊 安全審計標記

以下區域為 Heimdall 重點審查範圍：

| # | 模組 | 區域 | 風險等級 | 標記 |
|---|------|------|---------|------|
| S1 | resource/proof | proof_hash 不可移植 | 🔴 | 需修復 |
| S2 | resource/types | Ad 簽名未驗證 | 🔴 | 需修復 |
| S3 | p2p+identity | PeerId/DID 無綁定 | 🔴 | 需修復 |
| S4 | crypto | Nonce 構造非標準 | 🟡 | 建議改進 |
| S5 | resource/proof | Receipt 無簽名 | 🟡 | Phase 4 |
| A5 | p2p/network | BroadcastStructured 濫用 | 🟡 | 需修復 |
| A6 | p2p/handler | Accept 匹配邏輯 | 🟡 | 需修復 |
| C4 | resource/session | Session ID 泄露 | 🟢 | 建議改進 |

---

## ✅ 做得好的

1. **模組邊界清晰** — crypto/p2p/resource/identity/protocol 職責分明
2. **E2EE 實現紮實** — X25519 DH + ChaCha20Poly1305 + 會話輪換（counter+TTL）
3. **Session 密鑰安全** — secrecy crate 保護私鑰，zeroize on drop
4. **資源驗證完善** — ResourceAdvertisement.validate() 覆蓋 8 個檢查點
5. **Match Engine 設計合理** — 權重可配置，latency/reliability placeholder 保留擴展性
6. **測試覆蓋良好** — 254 單元測試 + 10 集成測試，邊界條件測試充分
7. **經濟模型參數化** — 雖未整合，但常量定義完整且有博弈論驗證
8. **Direct channel 取代 Gossipsub** — P0-3 改造方向正確，request-response 比 pub-sub 更適合點對點

---

## 📋 建議的修復優先級

| 優先級 | 項目 | 工作量 | 負責建議 |
|--------|------|--------|---------|
| 🔴 P0-1 | S1: proof_hash → blake3 | 30min | Rustacean |
| 🔴 P0-2 | S2: Ad 簽名生成+驗證 | 1-2h | 百鍊 |
| 🔴 P0-3 | A6: ResourceAccept 按 session_id 匹配 | 30min | Rustacean |
| 🔴 P0-4 | A5: BroadcastStructured 改用 Direct | 2h | 百鍊 |
| 🟡 P1-1 | S4: Nonce 加 salt | 30min | Rustacean |
| 🟡 P1-2 | A1: Engine 字段改 pub(crate) | 15min | Rustacean |
| 🟡 P1-3 | A2: MatchEngine 時間衰減 | 30min | 百鍊 |
| 🟡 P1-4 | A3: Allocation 追蹤簡化或完善 | 30min | Rustacean |
| 🟢 P2 | S3: PeerId/DID 綁定 | 2-4h | Phase 4 |
| 🟢 P2 | C1-C4 | 次要清理 | 1h | 誰有空誰做 |

**Heimdall 可在 P0-1~P0-4 修復後開始安全審計。**

---

*驚羽 🧠 — 2026-04-13 09:15 SGT*
*Phase 2B+3 架構審查完成*
