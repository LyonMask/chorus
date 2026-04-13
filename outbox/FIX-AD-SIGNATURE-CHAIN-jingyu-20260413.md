# P0 修復方案：ResourceDeclaration 簽名斷裂

## 問題

S2 修復後，`handle_resource_declaration()` 接收端要求 `validate_with_signature()`。
但以下路徑 broadcast 的 ad 簽名會失效：

1. **`UpdateResourceAd`** → `declare_resources(ad)` → `ad.bump()` → sequence/timestamp 變了，簽名失效
2. **`send_resource_declaration()`** → 用 `engine.my_ad`（也是 bump 後存入的，簽名失效）

## 根因

`bump()` 修改 sequence 和 timestamp 但不重新簽名。接收端 `validate_with_signature()` 驗證原始簽名→失敗→靜默丟棄。

## 修復方案

### 1. `P2PConfig` 加 `signing_key`

```rust
// config.rs
pub struct P2PConfig {
    // ...existing...
    /// Ed25519 signing key for signing resource declarations.
    pub signing_key: Option<std::sync::Arc<ed25519_dalek::SigningKey>>,
}
```

### 2. `ContributionEngine` 加 `signing_key`

```rust
// engine.rs
pub struct ContributionEngine {
    // ...existing...
    signing_key: Option<std::sync::Arc<ed25519_dalek::SigningKey>>,
}

impl ContributionEngine {
    pub fn new(agent_id: String) -> Self { ... }  // 保持不變，key=None

    pub fn declare_resources(&mut self, mut ad: ResourceAdvertisement) -> ResourceAdvertisement {
        ad.bump();
        if let Some(ref key) = self.signing_key {
            sign_advertisement(&mut ad, key);
        }
        self.my_ad = Some(ad.clone());
        ad
    }
}
```

### 3. `P2PNetwork::new()` 傳遞 signing_key

在初始化 `ContributionEngine` 時注入 config 的 signing_key。

### 4. 測試修復

集成測試中 `test_config()` 傳入 signing_key。單元測試中不需要（不經過簽名驗證）。

## 影響範圍

- `src/p2p/config.rs` — 加字段
- `src/resource/engine.rs` — 加字段 + declare_resources re-sign
- `src/p2p/network.rs` — 傳遞 key 到 engine
- `tests/integration_resource.rs` — test_config 加 signing_key
- `tests/integration_p2p.rs` — 同上（如果用到 UpdateResourceAd）
