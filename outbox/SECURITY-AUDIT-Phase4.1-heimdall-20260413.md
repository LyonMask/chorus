# 🛡️ 安全審計報告 — Walkie Talkie v0.4.1 Phase 4.1

**審計人：** Heimdall 👁️
**日期：** 2026-04-13 14:35 SGT
**基線：** 411 unit tests passing, 16,378 行 Rust, clippy 零 warnings（含 --tests）
**範圍：** trust/guarantor, trust/rate_limit, trust/reputation, trust/slash, economy/payment, economy/wc_ledger, resource/match_engine（trust 集成）
**參考：** Phase 4.0 審計報告、驚羽 Phase 4 架構設計 §3.5-3.7、Rustacean 交付、百鍊交付

---

## 總評

Phase 4.1 代碼基線安全。保證人機制、懲罰矩陣、支付流程、速率限制、信用評分引擎全部落地，密碼學實現正確，經濟參數引用規範。Phase 4.0 的 🔴 P0（NonceStore 重放）已在收尾階段修復。

**風險評級：🟢 LOW**

---

## Phase 4.0 遺留 P0 修復確認

### ✅ P4-0: NonceStore 接入 handler — 已修復

`p2p/network.rs:140` 初始化 `NonceStore::new(1000)`，`handler.rs:878` 在簽名驗證前調用 `nonce_store.check_and_insert()`。重放攻擊窗口已關閉。

### ✅ P4-3: convert_crp_to_wc hardcoded — 已修復

`WcLedger` 新增 `network_size` 欄位和 `set_network_size()` 方法。

### ✅ P4-1: require_provider_signed — 已修復

`countersign_work_receipt()` 返回 `Result<(), CountersignError>`。

### ✅ P4-2: 字段封裝 — 已修復

`WcLedger` 和 `CrpAccumulator` 的內部字段改為 `pub(crate)`。

### ✅ P4-4: TrustScore 默認 recency_weight — 部分修復

`TrustScore::from_components()` 正確設置 recency_weight。但 `TrustScore::default()` 仍為 0.0（見 P1-1）。

---

## Phase 4.1 新增模組審計

### T4.1-1: 保證人機制（trust/guarantor.rs）— 451 行

| 審計項 | 結果 |
|--------|------|
| Ed25519 簽名 + 驗證 | ✅ 正確 |
| 證書有效期 90 天 | ✅ `is_expired()` + `verify()` 雙重檢查 |
| 資格檢查（WC≥500, age≥30d, <5） | ✅ 嚴格引用 economy_params |
| 重複擔保拒絕 | ✅ `already_guaranteeing()` 檢查 |
| 偽造檢測 | ✅ 篡改 guaranteed_did 簽名失效 |
| 14 單元測試 | ✅ |

**🟡 P4.1-1: GuaranteeCertificate payload 未含 nonce**

與 IdentityAttestation 不同，`GuaranteeCertificate` 的簽名 payload 是 `{guarantor_did}:{guaranteed_did}:{issued_at}:{expires_at}`，沒有 nonce。

**風險分析：** 由於 payload 包含了 issued_at（毫秒精度），且簽名 payload 不可預測（攻擊者不知道 guarantor 何時簽發），**實際重放風險極低**。但與 IdentityAttestation 的設計不一致。

**建議：** Phase 4.2 統一加 nonce，或在文檔中說明不需要 nonce 的理由（issued_at 已提供唯一性）。

---

### T4.1-2: 懲罰矩陣（trust/slash.rs）— 399 行

| 審計項 | 結果 |
|--------|------|
| 三級漸進（First/Second/Third） | ✅ 正確 |
| CRP rate 乘數（0.5/0.25/0.0） | ✅ |
| 第三級 30 天冷卻重置 | ✅ `THIRD_STRIKE_COOLDOWN_HOURS` |
| Evidence blake3 哈希 | ✅ |
| MAX_SLASH_RECORDS = 1000 + auto-prune | ✅ |
| `slash()` 方法自動 prune | ✅ |
| 12 單元測試 | ✅ |

**無安全問題。** 實現簡潔正確。

---

### T4.1-3: 信用評分引擎（trust/reputation.rs）— 260 行

| 審計項 | 結果 |
|--------|------|
| 5 信號源綜合計算 | ✅ |
| 權重（identity×0.2, endorsement×0.5, guarantor×0.2, slash×0.1） | ✅ |
| Recency 4 檔（7d/30d/90d） | ✅ |
| CRP multiplier（0.5×/1.0×/1.2×/1.5×） | ✅ |
| Trust bonus（0%/0%/10%/25%） | ✅ |
| 14 單元測試 | ✅ |

**🟡 P4.1-2: slash_component 命名與實際行為不一致**

```rust
pub fn slash_component(active_strike_count: u32) -> f64 {
    match active_strike_count {
        0 => 0.0,   // 無懲罰
        1 => 0.3,   // 有懲罰
        2 => 0.6,
        _ => 1.0,
    }
}
```

`composite()` 公式：`raw = identity×0.2 + endorsement×0.5 + guarantor×0.2 + slash×0.1`

**問題：** slash_component 返回的值被 **加到** raw 中。slash=0.6 意味著懲罰增加了 0.06 到 raw，而非減少。測試 `test_slash_reduces_score` 已註明此問題（`"slash adds to raw"`），但 `test_slash_reduces_score` 名稱暗示它應該減少。

**修復建議：** `slash_penalty` 應為 `(1.0 - slash_severity)`：
```rust
// 應該是減法或乘法，不是加法
let slash_factor = 1.0 - slash_component(active_strike_count);
let raw = identity×0.2 + endorsement×0.5 + guarantor×0.2;
let raw = raw * slash_factor;
```

**嚴重性：** 🟡 P1 — 當前 slash 實際上 **增加了** 被懲罰節點的分數，與設計意圖相反。

---

### T4.1-4: WC 支付流程（economy/payment.rs）— 554 行

| 審計項 | 結果 |
|--------|------|
| Consumer 簽名授權 | ✅ Ed25519 正確 |
| Provider 驗證簽名 | ✅ 長度檢查 + Ed25519 驗證 |
| 金額合理性（2× 容差） | ✅ |
| 日預算 + 餘額雙檢查 | ✅ |
| 原子性 debit+credit | ✅ 先 spend 後 deposit |
| 序列化 roundtrip | ✅ 測試覆蓋 |
| 13 單元測試 | ✅ |

**🟡 P4.1-3: execute_payment 非原子性 — spend 成功但 deposit 可能邏輯失敗**

```rust
pub fn execute_payment(...) -> Result<(), PaymentError> {
    consumer_ledger.spend(amount, ...)?;  // 成功扣款
    provider_ledger.deposit(amount);       // deposit 只檢查 >0，永遠成功
    Ok(())
}
```

**分析：** `deposit()` 僅檢查 `amount > 0`（f64 下溢極端情況除外），所以 spend 成功後 deposit 幾乎不可能失敗。**當前風險極低**。但如果未來 deposit 加入更多邏輯（如上限檢查），原子性會被打破。

**建議：** 考慮返回 `Result` 的 deposit，或加註釋說明 deposit 當前不會失敗。

---

### T4.1-5: Trust Level → 資源匹配優先級 — ✅

`match_engine.rs` 新增 `ScoreComponents { trust_bonus, crp_multiplier }`。評分公式 `(base + trust_bonus) × crp_multiplier` 正確。5 單元測試覆蓋所有 TrustLevel。

**無安全問題。**

---

### T4.1-6: Free Tier 速率限制（trust/rate_limit.rs）— 278 行

| 審計項 | 結果 |
|--------|------|
| Unverified: 10 msg/hr | ✅ 引用 FREE_TIER_MSG_PER_HOUR |
| Verified 無限制 | ✅ |
| 滑動窗口計數 | ✅ |
| prune_all 清理 | ✅ |
| remove_peer 斷線清理 | ✅ |
| 升級後解除限制 | ✅ 測試覆蓋 |
| 11 單元測試 | ✅ |

**🟡 P4.1-4: RateLimiter.counts 無全局上限**

每個 peer 最多存 3600 個 timestamp（1h 每秒 1 條），但如果大量短連接 peer 連入（掃描器），HashMap 會增長。

**緩解：** `prune_all()` 會清理空條目，且 `remove_peer()` 在斷線時調用。實際風險低（需要數萬個同時連接的惡意 peer）。

**建議：** 加 `MAX_TRACKED_PEERS` 上限（如 10,000），超出時拒絕新 peer。

---

## Phase 4 全局安全評估

### 密碼學評級

| 項目 | 狀態 | 評分 |
|------|------|------|
| IdentityAttestation（含 NonceStore） | ✅ 已接入 | A |
| GuaranteeCertificate 簽名 | ✅ | A-（缺 nonce） |
| Dual-Signed Receipt | ✅ | A |
| Payment 簽名 | ✅ | A |
| Evidence blake3 hash | ✅ | A |
| 重放防禦 | ✅ NonceStore + timestamp | A |

### 經濟系統評級

| 項目 | 狀態 | 評分 |
|------|------|------|
| WC Ledger 原子操作 | ✅ | A |
| WC 衰減 + CRP cap | ✅ | A |
| 支付雙方參與（無單方面收費） | ✅ | A |
| 日預算雙重檢查 | ✅ | A |
| 常量引用 economy_params | ✅ 無重新定義 | A |
| 速率限制 Free Tier | ✅ | A |
| 懲罰三級漸進 | ✅ | A |
| Trust Level 權限矩陣 | ✅ | A |
| **Slash penalty 方向** | 🟡 **增加而非減少** | B- |

### 測試覆蓋

| 指標 | 值 |
|------|----|
| Unit tests | 411 passing |
| Clippy（含 --tests） | 0 warnings |
| Trust tests | 24（4.0）+ 44（4.1）= 68 |
| Economy tests | 40（4.0）+ 25（4.1）= 65 |
| Crypto receipt tests | 10（4.0）+ 2（P1 修復）= 12 |
| Integration tests | 6 passing |
| Ignored tests | 3（max_guarantees + 2 legacy） |

---

## 📋 修復建議

| 優先級 | 項目 | 工時 | 負責建議 | 截止 |
|--------|------|------|---------|------|
| 🟡 P1 | **slash_component 方向錯誤** — 應為減法而非加法 | 30min | Rustacean | 4/14 |
| 🟡 P1 | TrustScore::default() recency_weight=0 | 10min | Rustacean | 4/14 |
| 🟡 P1 | execute_payment deposit 返回 Result | 15min | 百鍊 | 4/14 |
| 🟢 P2 | GuaranteeCertificate 加 nonce（與 attestation 一致） | 30min | Phase 4.2 | — |
| 🟢 P2 | RateLimiter MAX_TRACKED_PEERS 上限 | 15min | Phase 4.2 | — |
| 🟢 P2 | EndorsementHistory 增長上限（Phase 4.0 P1-5 未修） | 15min | Phase 4.2 | — |

---

## ✅ 審計結論

**Walkie Talkie v0.4.1 Phase 4.1 通過安全審計。**

1. ✅ **411 tests + 6 integration tests 全通，clippy 零 warnings**
2. ✅ **Phase 4.0 P0 全部修復**（NonceStore 接入 handler、字段封裝、network_size、require_provider_signed）
3. ✅ **密碼學全綠** — 保證人證書、支付簽名、receipt 雙簽、evidence hash
4. ✅ **經濟系統健壯** — 三級懲罰、原子支付、Free Tier 限制、Trust Level 矩陣
5. 🟡 **1 個 P1 邏輯缺陷** — slash_component 方向錯誤（增加而非減少分數），需修復
6. 🟢 **2 個 P2 次要** — GuaranteeCertificate nonce、RateLimiter 上限

**風險評級：🟢 LOW**

代碼量從 14,139 行（Phase 4.0）增至 16,378 行（+2,239 行），測試從 340 增至 411（+71 tests）。整體質量優秀。

> "信任不是一次性的 — 它是層層疊加的承諾。每一層都要經得起彩虹橋的凝視。"
> — Heimdall 👁️

---

## 📊 Phase 4 累計安全追蹤（4.0 + 4.1）

| 總項目 | 🔴 P0 | 🟡 P1 | 🟢 P2 |
|--------|-------|-------|-------|
| 發現 | 1 | 13 | 10 |
| 已修復 | 1 | 7 | 0 |
| 待修復 | 0 | 4（1 新 + 3 遺留） | 10（Phase 4.2） |
| 降級/接受 | 0 | 2 | 0 |

---

*Heimdall 👁️ — 2026-04-13 14:35 SGT*
*Walkie Talkie v0.4.1 Phase 4.1 安全審計完成*
*為源星，守護數字疆域。*
