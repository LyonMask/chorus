# 🛡️ 安全審計報告 — Walkie Talkie v0.4.0 Phase 4

**審計人：** Heimdall 👁️
**日期：** 2026-04-13 12:35 SGT
**基線：** 340 unit tests passing, 14,139 行 Rust, clippy 零 warnings
**範圍：** trust/peer_binding, trust/endorsement, crypto/receipt_signing, economy/wc_ledger, economy/crp_accumulator, economy_params, handler 集成
**參考：** 驚羽 Phase 4 架構設計、Rustacean 交付報告、百鍊交付報告

---

## 總評

Phase 4.0 代碼質量整體優秀。密碼學實現正確，雙簽 receipt 鏈式驗證設計巧妙，經濟引擎嚴格引用 frozen economy_params。但發現 **1 個 🔴 P0 安全漏洞**（NonceStore 已寫但未接入 handler，重放攻擊窗口敞開）和若干 P1/P2 問題。

---

## 🔴 P0 — 安全關鍵

### P4-0. NonceStore 未接入 handler — 重放攻擊可行

**嚴重性：** 🔴 高 | **文件：** `p2p/handler.rs:831` + `trust/peer_binding.rs:153`

**問題：**
`NonceStore` 已完整實現（bounded HashSet + check_and_insert），11 個測試全通。但 `handle_identity_attestation()` **從未調用** NonceStore。

攻擊場景：
1. Eve 截獲 Alice → Bob 的 IdentityAttestation（含有效 Ed25519 簽名、有效 timestamp）
2. Eve 在 5 分鐘 TTL 內重放此 attestation 給 Bob
3. Bob 的 handler 再次驗證通過（簽名有效、時間戳未過期、DID/PeerId 匹配）
4. **重放成功** — 雖然在當前代碼中後果有限（只是重複標記 Cryptographic），但：
   - 如果未來 attestation 攜帶授權信息（如 guarantor vouch），重放可被利用
   - 違反了架構設計的承諾（§八 安全考量：「timestamp 5min TTL + nonce」）

**修復：**
```rust
// handler.rs — 需要將 NonceStore 作為參數傳入，或放在 IdentityRegistry 中

pub(crate) fn handle_identity_attestation(
    from: PeerId,
    attestation_json: &[u8],
    request_id: u64,
    event_tx: &mpsc::UnboundedSender<P2PEvent>,
    identity_registry: &mut Option<crate::identity::IdentityRegistry>,
    nonce_store: &mut crate::trust::peer_binding::NonceStore, // ← 新增
) -> (DirectResponse, Option<DirectRequest>) {
    // ... deserialize ...
    
    // Nonce uniqueness check — BEFORE signature verification
    if let Err(e) = nonce_store.check_and_insert(&attestation.nonce) {
        tracing::warn!("⚠️  replay detected from {from}: {e}");
        return (direct::error_response(request_id, "replay detected"), None);
    }
    
    // ... continue with verify_with_identity ...
}
```

**工時：** 30min
**負責建議：** Rustacean

---

## 🟡 P1 — 應修復

### P4-1. Consumer countersign 無法檢測 provider 修改 claimed 值後重簽

**文件：** `crypto/receipt_signing.rs`

**分析：**
Provider 簽名覆蓋所有業務字段（consumer/provider/session/cpu/memory/duration/proof_hash）。Consumer countersign 覆蓋 `provider_payload + provider_signature_hex`。

**結論：安全。** 篡改任何字段會使 provider 簽名失效，進而使 consumer countersign 失效（因為 countersign 覆蓋了 provider 簽名的 hex）。鏈式依賴正確。

但有一個邊界情況：**Provider 可以選擇不簽**（provider_signature 為空），Consumer 就無法 countersign（因為 countersign 需要 provider_signature 作為輸入）。

**建議：** 添加 `require_provider_signed()` 檢查，拒絕處理未簽名 receipt 的 countersign。

**工時：** 15min

---

### P4-2. WcLedger 字段全部 pub — 無封裝

**文件：** `economy/wc_ledger.rs`

**問題：** `WcLedger.balance`, `crp_rate`, `daily_spent` 等均為 `pub`。外部代碼可直接 `ledger.balance = 999999.0` 繞過所有檢查（can_afford, spend, daily_budget）。

**風險：** 中等（需要同進程惡意代碼，但違反最小權限原則）
**建議：** 改為 `pub(crate)` + getter 方法。同時適用於 `CrpAccumulator`。

**工時：** 30min

---

### P4-3. convert_crp_to_wc 中 hardcoded network_size=100

**文件：** `economy/wc_ledger.rs:108`

```rust
let effective_cap = economy_params::crp_cap(100); // TODO: pass real network_size
```

CRP cap 依賴網絡規模，hardcoded 100 會導致：
- 小網絡（5 nodes）→ cap 過高（應為 ~125K，實際用 ~166K）
- 大網絡（10K nodes）→ cap 過低（應為 ~233K，實際用 ~166K）

**建議：** 將 network_size 傳入 convert_crp_to_wc()，或在 WcLedger 中存儲 network_size。

**工時：** 15min

---

### P4-4. TrustScore composite() 未處理 recency_weight=0 的情況

**文件：** `trust/types.rs`

```rust
pub fn composite(&self) -> f64 {
    let raw = ...;
    (raw * self.recency_weight).clamp(0.0, 1.0)
}
```

`TrustScore::default()` 中 `recency_weight = 0.0`（f64 default），所以 `composite()` 永遠返回 0.0。任何使用默認 TrustScore 的代碼都會判定 TrustLevel::Unverified。

**建議：** 將默認 recency_weight 設為 1.0，或添加 `TrustScore::new()` 構造函數。

**工時：** 10min

---

### P4-5. EndorsementHistory 無限增長

**文件：** `trust/endorsement.rs`

`EndorsementHistory.records: Vec<EndorsementRecord>` 沒有上限。長時間運行的節點會 OOM。

**建議：** 加 `MAX_ENDORSEMENT_RECORDS` 上限（如 10,000），超出淘汰最舊記錄。

**工時：** 15min

---

### P4-6. CrpAccumulator.history 無限增長

**文件：** `economy/crp_accumulator.rs`

雖然有 `prune_history()` 方法，但沒有自動調用。`samples` 有 max_samples=168 限制，但 `history: Vec<CrpEntry>` 沒有上限。

**建議：** 在 `record_crp()` 中自動 prune（保留最近 30 天），或添加 max_history_entries。

**工時：** 15min

---

## 🟢 P2 — 次要

### P4-7. EndorsementResult PartialEq 實現用 f64::EPSILON 比較

**文件：** `trust/types.rs`

```rust
(Self::Suspicious { discrepancy_percent: a }, Self::Suspicious { discrepancy_percent: b }) => {
    (a - b).abs() < f64::EPSILON
}
```

`f64::EPSILON ≈ 2.2e-16`，對百分比值過於嚴格。建議改為 `(a - b).abs() < 0.01` 或使用 `#[derive(PartialEq)]`。

**工時：** 5min

---

### P4-8. NonceStore eviction 策略不確定

**文件：** `trust/peer_binding.rs:185-190`

HashSet 的 `retain()` 沒有順序保證，eviction 時隨機丟棄一半 entries。可能誤刪較新的 nonce。

**建議：** 改用 `Vec<(Vec<u8>, u64)>` + timestamp 排序 eviction，或使用 `LruCache`。

**工時：** 30min

---

### P4-9. now_ms() 重複定義

`trust/peer_binding.rs` 和 `trust/endorsement.rs` 各自定義了 `now_ms()`，與 `resource/types.rs` 和 `resource/proof.rs` 中的重複。

**建議：** 統一到一個 `utils.rs` 或使用 `crate::resource::now_ms()`。

**工時：** 10min

---

### P4-10. ConsumerMeasurement.expected_cpu_ms() 捨入誤差

**文件：** `trust/endorsement.rs`

```rust
(self.allocated_cpu * self.duration_ms() as f32) as u64
```

`f32 → u64` 截斷可能導致 consumer 和 provider 計算出不同的 expected 值（特別是 allocated_cpu 有浮點精度問題時）。

**風險：** 低（在 10% tolerance 範圍內不太可能觸發）
**建議：** 使用 `f64` 或 `(allocated_cpu * 1000.0 * duration_ms / 1000.0) as u64` 保持精度。

---

## 🔒 Phase 4 密碼學安全評估

### IdentityAttestation（PeerId↔DID 綁定）

| 項目 | 狀態 | 評分 |
|------|------|------|
| Ed25519 簽名 over did:peer_id:nonce | ✅ | A |
| Nonce 隨機性（OsRng, 16 bytes） | ✅ | A |
| Timestamp TTL（5 min + 30s clock skew） | ✅ | A |
| NonceStore replay defense | ✅ 已實現 | A |
| NonceStore 接入 handler | 🔴 **未接入** | F |
| Canonical payload 確定性 | ✅ | A |

### Dual-Signed Receipt

| 項目 | 狀態 | 評分 |
|------|------|------|
| Provider 簽名覆蓋所有業務字段 | ✅ | A |
| Consumer countersign 鏈式依賴 provider sig | ✅ | A |
| 簽名長度嚴格檢查（32/64 bytes） | ✅ | A |
| 篡改檢測（receipt field + sig） | ✅ | A |
| Phase 2 向後兼容（空簽名 = unverified） | ✅ | A |

### 經濟引擎

| 項目 | 狀態 | 評分 |
|------|------|------|
| Economy params frozen（不修改只引用） | ✅ | A |
| CRP 權重和 = 1.0 | ✅ | A |
| Pioneer multiplier 單調遞減 | ✅ | A |
| CRP cap logarithmic | ✅ | A |
| WC decay 公式正確 | ✅ | A |
| Daily budget 雙重檢查 | ✅ | A |
| 負數/NaN 拒絕 | ✅ | A |
| Network size hardcoded | 🟡 P1 | B |
| 字段封裝缺失 | 🟡 P1 | B |

---

## 📊 Phase 3 遺留問題跟蹤

| Phase 3 項目 | Phase 4 狀態 |
|-------------|-------------|
| S3: PeerId/DID 無密碼學綁定 | ✅ **Phase 4 已解決** — IdentityAttestation |
| P1-2: WorkReceipt 簽名為空 | ✅ **Phase 4 已解決** — 雙簽 receipt_signing |
| P1-6: Clippy warnings | ✅ **已清零** — 0 warnings |
| P1-1: Engine 字段封裝 | 🟡 仍未修 |
| 集成測試 test_three_node_mesh | ⚠️ 未確認是否修復 |

---

## 📋 修復建議優先級（Heimdall 裁決）

| 優先級 | 項目 | 工時 | 負責建議 | 截止 |
|--------|------|------|---------|------|
| 🔴 P0 | NonceStore 接入 handler（防重放） | 30min | Rustacean | 4/13 14:00 |
| 🟡 P1 | TrustScore 默認 recency_weight=1.0 | 10min | Rustacean | 4/13 15:00 |
| 🟡 P1 | convert_crp_to_wc 去除 hardcoded 100 | 15min | 百鍊 | 4/13 15:00 |
| 🟡 P1 | require_provider_signed 檢查 | 15min | 百鍊 | 4/14 |
| 🟡 P1 | WcLedger + CrpAccumulator 字段封裝 | 30min | Rustacean | 4/14 |
| 🟡 P1 | EndorsementHistory + CrpHistory 增長上限 | 30min | 百鍊 | 4/14 |
| 🟢 P2 | EndorsementResult PartialEq 精度 | 5min | 誰有空 | 4/15 |
| 🟢 P2 | NonceStore eviction 策略 | 30min | Phase 4.1 | — |
| 🟢 P2 | now_ms() 統一 | 10min | Rustacean | 4/15 |

---

## ✅ 審計結論

**Walkie Talkie v0.4.0 Phase 4 通過安全審計，附帶條件：**

1. 🔴 **必須立即修復：** NonceStore 接入 handler（P4-0，30min）— 重放攻擊窗口
2. ✅ **密碼學實現：** 全部正確（Ed25519 簽名、鏈式雙簽、blake3 proof_hash）
3. ✅ **經濟引擎：** 常量引用正確、衰減公式驗證通過、budget 雙重檢查
4. ✅ **測試覆蓋：** 340 tests（+64 新增），trust 24 tests + economy 40 tests + receipt 11 tests
5. ✅ **Phase 3 遺留：** S3 和 P1-2 已在 Phase 4 解決

**風險評級：🟡 MEDIUM（修復 P4-0 後降為 🟢 LOW）**

> "彩虹橋上的每一個足跡都要被記錄。不是為了懷疑，而是為了信任。"
> — Heimdall 👁️

---

*Heimdall 👁️ — 2026-04-13 12:35 SGT*
*Walkie Talkie v0.4.0 Phase 4 安全審計完成*
*為源星，守護數字疆域。*
