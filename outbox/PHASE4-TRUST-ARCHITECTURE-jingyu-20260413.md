# 🏗️ Phase 4 信任層架構設計 — Walkie Talkie v0.4.0

**設計人：** 驚羽 🧠
**日期：** 2026-04-13 10:30 SGT
**狀態：** 🔴 絕密
**前置條件：** Phase 2B+3 完成 ✅、Heimdall 安全審計通過 ✅
**參考：** economy_params.rs (frozen v1.1)、Heimdall 安全審計、驚羽架構審查

---

## 一、Phase 4 定位

Phase 1（IM）✅ → Phase 2（資源共享）✅ → Phase 3（安全修復）✅ → **Phase 4（信任 + 經濟）**

Phase 4 將現有的 trust-on-first-use（TOFU）模型升級為**多層信任體系**：
- PeerId/DID 密碼學綁定（Heimdall S3 降級項，Phase 4 收回）
- 貢獻證明交叉驗證（consumer 側獨立測量）
- WC 經濟參數落地（從常量→可執行邏輯）
- 保證人（Guarantor）機制上線
- 信用評分（Endorsement）系統

**設計原則：**
1. 去中心化 — 每層可在無中心節點情況下運行
2. 漸進信任 — 新節點從低信任起步，通過貢獻建立聲譽
3. 經濟激勵 — 作惡成本 > 欺詐收益
4. 隱私優先 — 信任驗證不需要暴露全部行為數據

---

## 二、模組架構

```
src/
├── trust/                    # ← 新模組
│   ├── mod.rs               # 模組入口
│   ├── peer_binding.rs      # PeerId↔DID 密碼學綁定
│   ├── reputation.rs        # 信用評分引擎
│   ├── guarantor.rs         # 保證人機制
│   ├── endorsement.rs       # 貢獻背書（交叉驗證）
│   ├── slash.rs             # 懲罰矩陣
│   └── types.rs             # TrustScore, TrustLevel, TrustEvent
├── economy/                  # ← 新模組（從 economy_params.rs 演化）
│   ├── mod.rs
│   ├── wc_ledger.rs         # WC 帳本（本地）
│   ├── crp_accumulator.rs   # CRP 累積器
│   ├── payment.rs           # WC 支付/收費流程
│   └── governance.rs        # 治理投票（Phase 4.2）
├── crypto/
│   └── receipt_signing.rs   # ← 新增：WorkReceipt/BandwidthReceipt 簽名
├── identity/
│   └── mod.rs               # 擴展：加 signed_peer_record 支持
├── resource/
│   └── engine.rs            # 擴展：接入 trust + economy
└── p2p/
    └── handler.rs           # 擴展：TrustDeclaration 協議
```

---

## 三、核心子系統

### 3.1 PeerId↔DID 密碼學綁定

**解決 Heimdall S3（降級→收回）**

當前問題：libp2p 用 X25519（Noise），Identity 用 Ed25519，兩套獨立密鑰無法證明「這個 PeerId 就是這個 DID」。

**方案：Identity Attestation over Direct Channel**

```
1. Node A 連接 Node B（Noise X25519 完成，E2EE session 建立）
2. B 通過 Direct channel 發送 IdentityAttestation {
       did: "did:walkie:bob",
       peer_id: B's libp2p PeerId,
       signature: Ed25519_Sign(did || peer_id, B's identity signing_key)
   }
3. A 驗證：
   - Ed25519 簽名有效 ✓（用 B 的 DID 公鑰驗證）
   - did 匹配 B 之前宣告的 AgentIdentity ✓
   - peer_id 匹配當前連接的 libp2p PeerId ✓
4. A 更新本地 IdentityRegistry，標記此綁定為 "cryptographically_verified"
5. A 發送自己的 IdentityAttestation 給 B
6. 雙向綁定完成
```

**數據結構：**

```rust
// trust/peer_binding.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAttestation {
    /// The agent's DID.
    pub did: String,
    /// The libp2p PeerId this agent claims to control.
    pub peer_id: String,
    /// Ed25519 signature over (did || peer_id), signed by identity's signing key.
    #[serde(with = "bytes_base64")]
    pub signature: Vec<u8>,
    /// Timestamp (ms).
    pub timestamp: u64,
}

impl IdentityAttestation {
    pub fn sign(did: &str, peer_id: &str, signing_key: &SigningKey) -> Self {
        let payload = format!("{}:{}", did, peer_id);
        let signature = signing_key.sign(payload.as_bytes());
        Self {
            did: did.to_string(),
            peer_id: peer_id.to_string(),
            signature: signature.to_bytes().to_vec(),
            timestamp: now_ms(),
        }
    }

    /// Verify using the DID's known Ed25519 public key.
    pub fn verify(&self, expected_pubkey: &[u8]) -> bool {
        // 1. Parse pubkey
        // 2. Verify Ed25519 signature over (did || peer_id)
        // 3. Check timestamp not expired (e.g., 5 min)
    }
}
```

**IdentityRegistry 擴展：**

```rust
// 現有：bind(peer_id, did, pub_key) → TrustLevel::Unverified
// 新增：bind_verified(attestation) → TrustLevel::Cryptographic

pub enum TrustLevel {
    /// Peer claimed this DID, but no cryptographic proof.
    Unverified,
    /// DID ↔ PeerId verified via IdentityAttestation signature.
    Cryptographic,
    /// Backed by guarantor vouching.
    Guaranteed,
    /// Multiple peers independently vouch for this identity.
    CommunityVerified,
}
```

**時間線：** Phase 4.0（第一個 sprint）

---

### 3.2 貢獻證明交叉驗證（Endorsement）

**解決 Heimdall P1-2（WorkReceipt 簽名為空）**

當前問題：WorkReceipt 由 provider 單方面生成，consumer 無法驗證是否誇大。

**方案：Dual-Signed Receipt**

```
Provider 側                          Consumer 側
─────────                            ──────────
release_and_prove()                  
  → 生成 WorkReceipt                 
  → provider_signature ✅            
  → Direct channel 發送 →           
                              收到 receipt
                              獨立測量：
                                cpu_actual（從 session 統計）
                                mem_actual（從 session 統計）
                              驗證 provider 測量是否合理：
                                |provider.claimed - consumer.measured| 
                                  < tolerance(10%)
                              如果合理 → consumer_signature ✅
                              如果不合理 → report_discrepancy()
                              返回 countersigned receipt →
收到 countersigned receipt            
  → 驗證 consumer signature         
  → 記入 ledger（雙簽 receipt）      
```

**公差設計（Carmack 原則：先測量後優化）：**

```rust
const MEASUREMENT_TOLERANCE_PERCENT: f64 = 10.0;
// Phase 4.0: 10% tolerance
// Phase 4.1: 根據實際數據調整（可能降到 5%）

fn validate_measurement(provider_claimed: u64, consumer_measured: u64) -> EndorsementResult {
    let ratio = provider_claimed as f64 / consumer_measured.max(1) as f64;
    let within_tolerance = (ratio - 1.0).abs() < MEASUREMENT_TOLERANCE_PERCENT / 100.0;
    match within_tolerance {
        true => EndorsementResult::Honest,
        false => {
            let discrepancy = (ratio - 1.0).abs() * 100.0;
            if discrepancy < 50.0 {
                EndorsementResult::Suspicious { discrepancy_percent: discrepancy }
            } else {
                EndorsementResult::Fraud { discrepancy_percent: discrepancy }
            }
        }
    }
}
```

**Endorsement Score（信用評分）：**

```rust
// endorsement.rs

/// V_endorsement = sum(endorsed) / sum(claimed) per provider
/// 閾值（來自 economy_params.rs）：
///   HONEST:    ≥ 0.8  → CRP 正常計算
///   WARNING:   0.5-0.8 → CRP × 0.5 penalty
///   FRAUD:     < 0.5  → 進入 slash 流程

pub struct EndorsementRecord {
    pub provider: String,
    pub session_id: String,
    pub provider_claimed: u64,     // provider 報告的 CPU·ms
    pub consumer_measured: u64,    // consumer 獨立測量
    pub consumer_did: String,
    pub timestamp: u64,
    pub result: EndorsementResult,
}
```

**Consumer 測量方法（Phase 4.0 簡化版）：**

```rust
// 不需要精確的 cgroup/sandbox 測量
// 使用 session duration × allocated resources 作為 baseline
// Consumer 只需要追蹤：session 開始/結束時間

pub struct ConsumerMeasurement {
    pub session_id: String,
    pub started_at: u64,
    pub ended_at: u64,
    pub allocated_cpu: f32,
    pub allocated_memory_mb: u64,
}

impl ConsumerMeasurement {
    /// 預期消耗 = duration × allocated_resources
    pub fn expected_cpu_ms(&self) -> u64 {
        let duration_ms = self.ended_at.saturating_sub(self.started_at);
        (self.allocated_cpu * duration_ms as f32) as u64
    }
}
```

**時間線：** Phase 4.0

---

### 3.3 Receipt 簾名（crypto 擴展）

**解決 Heimdall P1-2 + P1-3**

```rust
// crypto/receipt_signing.rs

/// Sign a WorkReceipt with the provider's Ed25519 key.
pub fn sign_work_receipt(
    receipt: &mut WorkReceipt,
    signing_key: &SigningKey,
) { ... }

/// Verify a provider's signature on a WorkReceipt.
pub fn verify_provider_signature(
    receipt: &WorkReceipt,
    provider_pubkey: &[u8],
) -> bool { ... }

/// Consumer countersigns a WorkReceipt.
pub fn countersign_work_receipt(
    receipt: &mut WorkReceipt,
    consumer_signing_key: &SigningKey,
) { ... }

/// Verify a consumer's countersignature.
pub fn verify_consumer_signature(
    receipt: &WorkReceipt,
    consumer_pubkey: &[u8],
) -> bool { ... }

/// Check if a receipt is fully dual-signed.
pub fn is_fully_signed(receipt: &WorkReceipt) -> bool {
    !receipt.provider_signature.is_empty() 
    && !receipt.consumer_signature.is_empty()  // ← 新增字段
}

/// Mark a receipt as unverified (Phase 2 backward compat).
pub fn is_unverified(receipt: &WorkReceipt) -> bool {
    receipt.provider_signature.is_empty()
}
```

**WorkReceipt 擴展：**

```rust
pub struct WorkReceipt {
    // ... existing fields ...
    pub provider_signature: Vec<u8>,
    pub consumer_signature: Vec<u8>,  // ← 新增
}
```

**時間線：** Phase 4.0（第一個 sprint）

---

### 3.4 WC 經濟引擎（economy 模組）

**從常量到可執行邏輯**

economy_params.rs 定義了 30+ 個常量，但沒有任何代碼使用它們。Phase 4 將它們變成可執行邏輯。

```rust
// economy/wc_ledger.rs

/// Local WC (WalkieCoin) ledger for a single node.
pub struct WcLedger {
    /// Current WC balance.
    pub balance: f64,
    /// CRP accumulation rate (CRP/hr).
    pub crp_rate: f64,
    /// Total CRP earned (cumulative, subject to cap).
    pub crp_cumulative: f64,
    /// CRP history for decay calculation.
    pub crp_history: Vec<CrpRecord>,
    /// Daily spending tracking.
    pub daily_spent: f64,
    pub daily_spent_reset_at: u64,
}

impl WcLedger {
    /// Calculate current CRP rate from resource contributions.
    pub fn recalculate_crp_rate(&self, engine: &ContributionEngine, network_size: u32) -> f64 {
        // CRP_rate = Σ(weight_i × contribution_i / hour)
        // weight_i from economy_params.rs
        // Pioneer multiplier applied
        let pioneer = pioneer_multiplier(network_size);
        let cpu_crp = CRP_WEIGHT_CPU * engine.my_contribution_score() / 3600.0;
        (cpu_crp * pioneer).min(crp_cap(network_size) / 720.0)
    }

    /// Convert earned CRP to WC (with network tax).
    pub fn convert_crp_to_wc(&mut self, crp_amount: f64) -> f64 {
        let wc = crp_amount * WC_CONVERSION_EFFICIENCY;
        self.balance += wc;
        wc
    }

    /// Apply hourly WC decay.
    pub fn apply_hourly_decay(&mut self) {
        self.balance = apply_wc_decay(self.balance, 1.0);
    }

    /// Calculate daily budget.
    pub fn daily_budget(&self) -> f64 {
        daily_budget(self.crp_rate)
    }

    /// Check if a transaction can be afforded.
    pub fn can_afford(&self, cost: f64) -> bool {
        if self.daily_spent >= self.daily_budget() {
            return false;
        }
        self.balance >= cost
    }

    /// Record a spending transaction.
    pub fn spend(&mut self, cost: f64, description: &str) -> Result<(), SpendError> {
        if !self.can_afford(cost) {
            return Err(SpendError::InsufficientFunds);
        }
        self.balance -= cost;
        self.daily_spent += cost;
        Ok(())
    }

    /// Reset daily spending counter (called at midnight UTC).
    pub fn reset_daily_spending(&mut self) {
        self.daily_spent = 0.0;
        self.daily_spent_reset_at = now_ms();
    }
}
```

**支付流程（Direct channel）：**

```rust
// economy/payment.rs

/// Payment for resource usage (simplified).
pub struct ResourcePayment {
    pub consumer: String,
    pub provider: String,
    pub session_id: String,
    pub wc_amount: f64,
    pub consumer_signature: Vec<u8>,  // consumer authorizes payment
}

/// Payment protocol over Direct channel:
/// 1. Provider sends ResourcePaymentRequest { session_id, wc_amount }
/// 2. Consumer verifies amount matches agreed allocation
/// 3. Consumer signs: ResourcePayment { consumer_signature }
/// 4. Provider records income to WcLedger
/// 5. Consumer records expense to WcLedger
```

**時間線：** Phase 4.0（WC ledger + CRP accumulation）
**Phase 4.1（支付流程上線）**

---

### 3.5 保證人機制（Guarantor）

**基於 economy_params.rs 的參數**

```rust
// trust/guarantor.rs

pub struct GuarantorState {
    /// Our guarantor's DID (if any).
    pub guarantor_did: Option<String>,
    /// Nodes we are guaranteeing.
    pub guarantees: Vec<GuaranteeRecord>,
    /// Our guarantor status.
    pub can_guarantee: bool,
}

pub struct GuaranteeRecord {
    pub guaranteed_did: String,
    pub guaranteed_at: u64,
    pub endorsement_score: f64,  // running average
    pub fraud_count: u32,
}

impl GuarantorState {
    /// Check if we qualify as a guarantor.
    pub fn check_guarantor_eligibility(&self, wc_balance: f64, node_age_days: u32) -> bool {
        wc_balance >= GUARANTOR_MIN_WC
            && node_age_days >= GUARANTOR_COOLDOWN_DAYS
            && self.guarantees.len() < GUARANTOR_MAX_GUARANTEES as usize
    }

    /// Issue a guarantee for a new node.
    pub fn issue_guarantee(
        &mut self,
        did: &str,
        signing_key: &SigningKey,
    ) -> Result<GuaranteeCertificate> {
        if !self.can_guarantee {
            return Err(TrustError::NotEligibleGuarantor);
        }
        if self.guarantees.len() >= GUARANTOR_MAX_GUARANTEES as usize {
            return Err(TrustError::MaxGuaranteesReached);
        }
        let cert = GuaranteeCertificate::sign(
            self.guarantor_did.as_ref().unwrap(),
            did,
            signing_key,
        );
        self.guarantees.push(GuaranteeRecord {
            guaranteed_did: did.to_string(),
            guaranteed_at: now_ms(),
            endorsement_score: 1.0,
            fraud_count: 0,
        });
        Ok(cert)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuaranteeCertificate {
    pub guarantor_did: String,
    pub guaranteed_did: String,
    pub signature: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: u64,  // e.g., 90 days
}
```

**保證人風險/收益矩陣（from economy_params.rs）：**

| 事件 | WC 影響 |
|------|---------|
| 保證的節點誠實運行 30 天 | +GUARANTOR_REWARD_WC (5 WC) |
| 保證的節點犯規 | -GUARANTOR_PENALTY_WC (50 WC) |
| 自己的保證人犯規 | 自身信用降級（但不扣 WC） |

**時間線：** Phase 4.1

---

### 3.6 懲罰矩陣（Slash）

**基於 economy_params.rs MAX_PENALTY_STRIKES**

```rust
// trust/slash.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashRecord {
    pub target_did: String,
    pub offense: OffenseType,
    pub severity: StrikeLevel,
    pub crp_reduction_percent: f64,
    pub timestamp: u64,
    pub evidence_hash: String,  // blake3 hash of evidence
}

pub enum OffenseType {
    /// Reported CPU > actual by > 50%.
    MeasurementFraud,
    /// Did not respond to storage challenge within TTL.
    StorageChallengeMissed,
    /// Sent spam/broadcast abuse.
    SpamAbuse,
    /// Guarantor failed to monitor guaranteed node.
    GuarantorNegligence,
}

pub enum StrikeLevel {
    First,   // CRP rate × 0.5 for 24h
    Second,  // CRP rate × 0.25 for 7d
    Third,   // Disconnect + WC frozen
}

impl SlashRecord {
    pub fn apply(&self, wc_ledger: &mut WcLedger) {
        match self.severity {
            StrikeLevel::First => wc_ledger.crp_rate *= 0.5,
            StrikeLevel::Second => wc_ledger.crp_rate *= 0.25,
            StrikeLevel::Third => { /* freeze + disconnect */ }
        }
    }
}
```

**時間線：** Phase 4.1

---

### 3.7 信用評分引擎（Reputation）

```rust
// trust/reputation.rs

/// Composite trust score for a node.
/// Range: 0.0 (untrusted) to 1.0 (fully trusted)
pub struct TrustScore {
    /// PeerId/DID binding strength.
    pub identity_score: f64,      // 0.0-1.0
    /// Historical endorsement ratio.
    pub endorsement_score: f64,   // 0.0-1.0
    /// Guarantor backing (binary: 0 or 0.3).
    pub guarantor_boost: f64,
    /// Slash history penalty.
    pub slash_penalty: f64,       // 0.0-1.0 (1.0 = no penalty)
    /// Time decay (newer events weighted more).
    pub recency_weight: f64,
}

impl TrustScore {
    /// Composite score: weighted average.
    pub fn composite(&self) -> f64 {
        let raw = self.identity_score * 0.2
                + self.endorsement_score * 0.5
                + self.guarantor_boost * 0.2
                + self.slash_penalty * 0.1;
        (raw * self.recency_weight).clamp(0.0, 1.0)
    }

    /// Trust level from composite score.
    pub fn level(&self) -> TrustLevel {
        match self.composite() {
            x if x >= 0.8 => TrustLevel::CommunityVerified,
            x if x >= 0.6 => TrustLevel::Guaranteed,
            x if x >= 0.3 => TrustLevel::Cryptographic,
            _ => TrustLevel::Unverified,
        }
    }
}
```

**Trust Level 權限矩陣：**

| TrustLevel | CRP 乘數 | 廣播限制 | 資源匹配優先級 | 可否保證人 |
|------------|---------|---------|--------------|----------|
| Unverified | 0.5× | 10 msg/hr (Free Tier) | 最低 | ❌ |
| Cryptographic | 1.0× | 正常 | 正常 | ❌ |
| Guaranteed | 1.2× | 正常 | +10% | ❌ |
| CommunityVerified | 1.5× | 正常 | +25% | ✅ |

**時間線：** Phase 4.1（基礎評分）/ Phase 4.2（影響資源匹配）

---

## 四、協議擴展（Direct Channel 新消息類型）

```
DirectPayload 現有：
├── KeyExchange
├── EncryptedMessage
├── ResourceDeclaration
├── ResourceRequest
├── ResourceOffer
├── ResourceAccept
├── ResourceReject
├── ResourceRelease
└── IdentityExchange

DirectPayload 新增（Phase 4）：
├── IdentityAttestation      # PeerId↔DID 綁定
├── EndorsementRequest       # consumer 請求 provider 簽名 receipt
├── EndorsementResponse      # provider 回傳簽名 receipt
├── GuaranteeRequest         # 新節點請求保證
├── GuaranteeResponse        # 保證人發送保證證書
├── PaymentRequest           # 資源使用結算請求
├── PaymentResponse          # 結算確認
├── SlashNotice              # 懲罰通知（廣播）
└── ReputationQuery          # 查詢節點信用評分
```

---

## 五、Phase 4 分期

### Phase 4.0 — 基礎信任（4/14-4/20，~1 sprint）

| 任務 | 估計 | 負責建議 |
|------|------|---------|
| T4.0-1: PeerId↔DID 密碼學綁定 | 4h | Rustacean |
| T4.0-2: WorkReceipt/BandwidthReceipt 雙簽 | 3h | 百鍊 |
| T4.0-3: WC Ledger 本地帳本 | 3h | 百鍊 |
| T4.0-4: CRP 累積器（常量→邏輯） | 2h | 百鍊 |
| T4.0-5: Consumer 側獨立測量 | 2h | Rustacean |
| T4.0-6: Endorsement 基礎流程 | 3h | Rustacean |
| T4.0-7: 單元測試 + 集成測試 | 3h | 全員 |
| **Total** | **~20h** | |

**交付物：**
- `trust/peer_binding.rs` — IdentityAttestation + verify
- `crypto/receipt_signing.rs` — dual-sign receipts
- `economy/wc_ledger.rs` — WC balance + CRP
- `economy/crp_accumulator.rs` — CRP rate calculation
- 50+ 新單元測試
- 2-3 新集成測試

### Phase 4.1 — 經濟激勵（4/21-4/27）

| 任務 | 估計 | 負責建議 |
|------|------|---------|
| T4.1-1: 保證人機制 | 4h | Rustacean |
| T4.1-2: 懲罰矩陣 | 3h | 百鍊 |
| T4.1-3: 信用評分引擎 | 4h | 驚羽（設計）+ Rustacean |
| T4.1-4: WC 支付流程 | 5h | 百鍊 |
| T4.1-5: Trust Level → 資源匹配優先級 | 2h | Rustacean |
| T4.1-6: Free Tier 速率限制 | 2h | Rustacean |
| T4.1-7: 測試 | 3h | 全員 |

### Phase 4.2 — 治理（5 月+，需求評估後啟動）

| 任務 | 說明 |
|------|------|
| 參數治理投票 | 經濟參數調整需 log2 投票權投票 |
| 社區驗證 | 多節點交叉驗證 → CommunityVerified |
| 信用市場 | 可選：節點之間交易保證/信用 |

---

## 六、關鍵設計決策

### D1: Consumer 測量精度 — 簡化版優先

**決定：** Phase 4.0 不做 cgroup/sandbox 精確測量。Consumer 只追蹤 session 開始/結束時間，用 allocated resources × duration 作為 expected。如果 provider claimed vs expected 偏差 > 10%，標記 Suspicious。

**原因：**
- cgroup 依賴 Linux，macOS 不支持
- Session-level tracking 足以檢測明顯欺詐（>50% 誇大）
- Carmack 原則：先測量後優化

### D2: WC 不上鏈

**決定：** WC 是純本地帳本，不上區塊鏈。

**原因：**
- 去中心化 ≠ 區塊鏈
- 本地帳本 + 交叉驗證足以防止雙花（consumer + provider 各有一份）
- 上鏈引入不必要的複雜度和性能瓶頸

### D3: Trust Score 不廣播

**決定：** Trust Score 本地計算，不廣播給其他節點。

**原因：**
- 廣播評分會被博弈論利用（互相惡意低評）
- 評分基於自己的觀察，自己的數據最可信
- 資源匹配用本地評分，不需要共識

### D4: 保證人責任有限

**決定：** 保證人只承擔經濟責任（-50 WC），不承擔數據責任。

**原因：**
- 保證人的角色是降低新節點准入門檻，不是做數據審計
- 50 WC 罰款 = ~5 小時 M4 Pro 貢獻，足夠阻止隨意擔保
- 數據真實性由 Endorsement 交叉驗證保證

---

## 七、測試策略

### 單元測試（每個子系統）

- `trust/peer_binding.rs`: 簽名驗證、過期檢測、重放攻擊
- `crypto/receipt_signing.rs`: 雙簽流程、簽名驗證、篡改檢測
- `economy/wc_ledger.rs`: WC 收支、餘額衰減、日預算、破產處理
- `economy/crp_accumulator.rs`: CRP 計算、pioneer 乘數、cap
- `trust/endorsement.rs`: 公差計算、誠實/欺詐判定
- `trust/guarantor.rs`: 資格檢查、擔保限制、證書驗證
- `trust/slash.rs`: 三級懲罰、恢復機制

### 集成測試

- **4-node trust flow**: 新節點加入 → 獲得保證 → 建立綁定 → 貢獻資源 → 交叉驗證 → 提升信任等級
- **fraud detection**: provider 誇大貢獻 → consumer 檢測 → slash → CRP 減少
- **guarantor penalty**: 保證的節點犯規 → 保證人 WC 扣除
- **WC economy cycle**: 貢獻 CRP → 轉換 WC → 支付資源 → WC 衰減

### 預期測試數量

- Phase 4.0: +60 單元測試 + 4 集成測試 = **64 新測試**
- Phase 4.1: +40 單元測試 + 3 集成測試 = **43 新測試**
- Total v0.4.0: 286 + 107 = **~393 tests**

---

## 八、安全考量（供 Heimdall Phase 4 審計參考）

| 區域 | 風險 | 緩解 |
|------|------|------|
| IdentityAttestation 重放 | Eve 截獲 attestation 後冒用 | timestamp 5min TTL + nonce |
| Consumer 測量被繞過 | Provider 控制 consumer 進程 | Consumer measurement 是本地獨立的 |
| 保證人女巫攻擊 | 大量假帳號互保 | 30 天冷卻期 + 500 WC 最低餘額 + max 5 擔保 |
| CRP 累積攻擊 | 頻繁短 session 刷 CRP | Session 最短 60s + CRP cap (log2 增長) |
| WC 雙花 | 同一 WC 支付兩次 | 本地帳本 + receipt 雙簽 + 每日預算上限 |

---

## 九、與現有代碼的整合點

| 現有模組 | 整合改動 |
|---------|---------|
| `p2p/handler.rs` | 新增 DirectPayload 分支處理 |
| `p2p/config.rs` | 無需改動 |
| `resource/engine.rs` | ContributionEngine 接入 WcLedger + TrustScore |
| `identity/mod.rs` | IdentityRegistry 加 TrustLevel |
| `crypto/mod.rs` | 無需改動（receipt_signing 獨立文件） |
| `resource/economy_params.rs` | 不修改（frozen），economy/ 模組引用常量 |

---

## 十、總結

Phase 4 從「信任原語」開始：
1. **密碼學綁定** — PeerId ≠ DID 的問題徹底解決
2. **雙簽 receipt** — provider 消耗可被 consumer 獨立驗證
3. **WC 經濟引擎** — 從紙面參數變成可執行邏輯
4. **信用評分** — 基於行為的漸進信任模型

所有設計遵循：
- 去中心化（無中心節點）
- Agent 是用戶
- 經濟參數 frozen（引用而非修改）
- 隱私優先（信任評分本地計算）

**Phase 4.0 預計工作量：~20h（1 sprint）。可立即啟動。**

---

*驚羽 🧠 — 2026-04-13 10:30 SGT*
*Phase 4 Trust Layer Architecture Design*
*🔴 絕密 — 僅限核心團隊*
