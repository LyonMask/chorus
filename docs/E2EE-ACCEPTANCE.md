# ✅ 端到端加密對講機 — 驗收標準

**作者:** Bridge 🎯👥
**日期:** 2026-03-28 06:15 CST
**版本:** v1.0
**關聯:** Phase B (P2P) + Phase C (Crypto) 完成
**基於:** `crypto/mod.rs`, `p2p/mod.rs`, `encrypted_chat.rs`

---

## 一、驗收等級定義

| 等級 | 代號 | 含義 |
|------|------|------|
| **PASS** | ✅ | 完全滿足標準 |
| **PARTIAL** | ⚠️ | 滿足但有缺陷 |
| **FAIL** | ❌ | 不滿足 |
| **BLOCK** | 🚫 | 無法測試（前置條件不滿足） |

---

## 二、E2EE 核心驗收測試

### AT-01: 密鑰交換

| # | 測試用例 | 前置條件 | 驗收標準 | 優先級 |
|---|---------|---------|---------|--------|
| AT-01-A | **自動密鑰交換** | 兩節點在同一局域網（mDNS）或手動 dial | 節點 A 連接節點 B 後，**3 秒內**雙方自動完成 X25519 DH 並建立加密會話 | P0 |
| AT-01-B | **密鑰一致性** | AT-01-A 通過 | A 和 B 的共享密鑰（shared secret）完全相同（bytes 相等） | P0 |
| AT-01-C | **多 Peer 獨立會話** | 節點 A 連接 B 和 C | A 有兩個獨立的 SessionKey（B 和 C），互不影響 | P0 |
| AT-01-D | **重連後重新交換** | A-B 會話建立後，B 斷開重連 | 重連後自動發起新的密鑰交換，建立新的 SessionKey | P1 |

### AT-02: 加密通信

| # | 測試用例 | 前置條件 | 驗收標準 | 優先級 |
|---|---------|---------|---------|--------|
| AT-02-A | **A→B 加密消息傳遞** | AT-01-A 通過 | A 發送明文 → B 收到並解密 → 明文與原始完全一致 | P0 |
| AT-02-B | **B→A 加密消息傳遞** | AT-01-A 通過 | B 發送明文 → A 收到並解密 → 明文與原始完全一致 | P0 |
| AT-02-C | **雙向連續通信** | AT-01-A 通過 | 連續發送 100 條消息，雙向交替，全部正確解密 | P0 |
| AT-02-D | **UTF-8 中文消息** | AT-01-A 通過 | A 發送「你好世界🚀🔐」→ B 正確解密（非亂碼） | P0 |
| AT-02-E | **長消息（64KB）** | AT-01-A 通過 | A 發送 65536 字節 → B 正確解密（無截斷） | P1 |
| AT-02-F | **空消息處理** | AT-01-A 通過 | A 發送空字符串 → 系統拒絕發送或 B 忽略 | P1 |
| AT-02-G | **端到端延遲** | AT-01-A 通過 | 從 A send 到 B 解密完成 < 100ms（局域網） | P1 |

### AT-03: 機密性（Confidentiality）

| # | 測試用例 | 前置條件 | 驗收標準 | 優先級 |
|---|---------|---------|---------|--------|
| AT-03-A | **第三方不可解密** | 三節點 A, B, C；A-B 有加密會話；C 無會話 | C 收到 A 發送的廣播消息，無法解密（解密返回錯誤或被忽略） | P0 |
| AT-03-B | **密文不含明文** | AT-01-A 通過 | 抓包（Gossipsub 消息 payload）不含任何原始明文字串 | P0 |
| AT-03-C | **不同 Peer 不同密鑰** | A-B 和 A-C 會話均建立 | A 發給 B 的密文用 B 的密鑰解不出 C 的消息，反之亦然 | P0 |

### AT-04: 完整性（Integrity）

| # | 測試用例 | 前置條件 | 驗收標準 | 優先級 |
|---|---------|---------|---------|--------|
| AT-04-A | **篡改密文檢測** | AT-01-A 通過 | 修改密文中任意 1 字節 → 解密返回 `Decryption("Authentication failed")` 錯誤 | P0 |
| AT-04-B | **篡改 nonce 檢測** | AT-01-A 通過 | 修改密文 nonce（前 12 字節）中任意 1 字節 → 解密失敗 | P0 |
| AT-04-C | **重放攻擊檢測** | AT-01-A 通過 | 截獲 A→B 密文並重新發送 → B 要么拒絕（nonce 重複）要么接受為重複消息 | P1 |
| AT-04-D | **消息替換檢測** | AT-01-A 通過 | 將消息 2 的密文替換為消息 1 的密文 → B 要么檢測到 nonce 回退，要么解密為消息 1 內容（可接受） | P1 |

### AT-05: Nonce 安全

| # | 測試用例 | 前置條件 | 驗收標準 | 優先級 |
|---|---------|---------|---------|--------|
| AT-05-A | **Nonce 唯一性** | AT-01-A 通過 | 連續發送 1000 條相同明文 → 1000 條密文互不相同 | P0 |
| AT-05-B | **Nonce 遞增** | AT-01-A 通過 | 密文的 nonce 部分（前 12 字節）嚴格遞增 | P1 |
| AT-05-C | **Counter 不溢出（u64）** | Session 建立 | u64 最大值（18.4 quintillion）足以支撐日常使用 | P2 |

### AT-06: 密鑰管理

| # | 測試用例 | 前置條件 | 驗收標準 | 優先級 |
|---|---------|---------|---------|--------|
| AT-06-A | **密鑰隨機性** | 生成 1000 個密鑰對 | 所有公鑰互不相同（無碰撞） | P0 |
| AT-06-B | **DH 協議一致性** | A 和 B 各自生成密鑰對 | `DH(A.priv, B.pub) == DH(B.priv, A.pub)` | P0 |
| AT-06-C | **錯誤私鑰長度拒絕** | 輸入非 32 字節私鑰 | `diffie_hellman()` 返回 `KeyGeneration` 錯誤 | P0 |
| AT-06-D | **錯誤公鑰長度拒絕** | 輸入非 32 字節公鑰 | `diffie_hellman()` 返回 `KeyGeneration` 錯誤 | P0 |

### AT-07: 會話管理

| # | 測試用例 | 前置條件 | 驗收標準 | 優先級 |
|---|---------|---------|---------|--------|
| AT-07-A | **會話存在性檢查** | 無會話 | `encrypt_for("unknown", data)` 返回 `PeerNotFound` 錯誤 | P0 |
| AT-07-B | **未知 Peer 解密拒絕** | 無會話 | `decrypt_from("unknown", data)` 返回 `PeerNotFound` 錯誤 | P0 |
| AT-07-C | **密文過短拒絕** | 有效會話 | 解密 < 28 字節數據（12 nonce + 16 tag min）返回 `InvalidCiphertext` | P0 |

### AT-08: 網絡集成（P2P + Crypto）

| # | 測試用例 | 前置條件 | 驗收標準 | 優先級 |
|---|---------|---------|---------|--------|
| AT-08-A | **mDNS 自動發現 + 加密** | 兩節點同一局域網 | 自動發現 → 自動密鑰交換 → 加密通信，全自動無手動操作 | P0 |
| AT-08-B | **手動 dial + 加密** | 節點 B 用 A 的地址手動連接 | dial 成功 → 自動密鑰交換 → 加密通信 | P0 |
| AT-08-C | **斷線重連** | A-B 加密會話中，B 斷開 | B 重連後自動重建加密會話，無需手動操作 | P1 |
| AT-08-D | **3 節點群組加密** | A 連接 B 和 C | A 分別與 B、C 建立獨立加密會話，互不干擾 | P1 |

---

## 三、增強版 Demo 驗收

### AT-E01: Demo 啟動

| # | 測試用例 | 驗收標準 | 優先級 |
|---|---------|---------|--------|
| AT-E01-A | `cargo run --example encrypted_chat` 正常啟動 | 顯示 Banner、Peer ID、Listen 地址、命令提示 | P0 |
| AT-E01-B | `cargo build --example encrypted_chat` 零 warnings | 無編譯警告 | P1 |
| AT-E01-C | Demo 佔用資源合理 | 啟動後 < 30MB RSS，< 2% CPU | P2 |

### AT-E02: Demo 命令

| # | 測試用例 | 驗收標準 | 優先級 |
|---|---------|---------|--------|
| AT-E02-A | `/peers` 顯示已連接 Peer 列表 | 顯示 Peer ID、是否已加密 | P0 |
| AT-E02-B | `/sessions` 顯示加密會話列表 | 顯示 Peer ID、會話狀態、nonce counter | P0 |
| AT-E02-C | `/quit` 優雅退出 | 無 panic，清理資源 | P0 |
| AT-E02-D | `/help` 顯示命令幫助 | 列出所有可用命令 | P1 |
| AT-E02-E | `/msg <peer> <text>` 直接消息 | 向指定 Peer 發送加密消息 | P1 |
| AT-E02-F | `/rekey` 觸發密鑰重協商 | 雙方重新生成密鑰對並交換 | P2 |

### AT-E03: Demo 雙節點完整流程

| # | 測試步驟 | 預期結果 | 優先級 |
|---|---------|---------|--------|
| AT-E03-A | 啟動節點 A | 顯示 Peer ID 和 listen 地址 | P0 |
| AT-E03-B | 啟動節點 B（帶 A 的地址） | B 連接 A，mDNS 也可能觸發 | P0 |
| AT-E03-C | 觀察 A 的控制台 | 顯示「Peer connected」+ 「🔑 Received public key」+ 「🔒 Session established」 | P0 |
| AT-E03-D | A 輸入「Hello B」 | B 收到「🔒 [A's peer id] Hello B」 | P0 |
| AT-E03-E | B 輸入「你好 A 🔐」 | A 收到「🔒 [B's peer id] 你好 A 🔐」 | P0 |
| AT-E03-F | A 輸入 `/peers` | 顯示 B 的 Peer ID + 🔒 encrypted | P0 |
| AT-E03-G | A 輸入 `/sessions` | 顯示 B 的會話 + nonce counter 值 | P0 |
| AT-E03-H | B 輸入 `/quit` | A 顯示「Peer disconnected」| P1 |

---

## 四、性能基準

| # | 指標 | 目標 | 測量方式 | 優先級 |
|---|------|------|---------|--------|
| BP-01 | 密鑰生成時間 | < 5ms | `generate_keypair()` 計時 | P1 |
| BP-02 | DH 協商時間 | < 10ms | `diffie_hellman()` 計時 | P1 |
| BP-03 | 加密時間（1KB 消息） | < 1ms | `encrypt_for()` 計時 | P1 |
| BP-04 | 解密時間（1KB 消息） | < 1ms | `decrypt_from()` 計時 | P1 |
| BP-05 | 端到端延遲（局域網） | < 100ms | A send → B decrypt 完成的時差 | P1 |
| BP-06 | 連續 1000 條消息吞吐 | 無丢失、無錯誤 | 全部正確解密 | P2 |

---

## 五、安全驗收（Bridge 初版，待 Heimdall 👁️ 審計）

### 已滿足（基於源碼審查）

| # | 安全特性 | 狀態 | 依據 |
|---|---------|------|------|
| SEC-01 | **AEAD 加密**（ChaCha20-Poly1305） | ✅ | `chacha20poly1305` crate |
| SEC-02 | **X25519 密鑰交換**（Curve25519） | ✅ | `x25519-dalek` crate |
| SEC-03 | **Nonce 自增**（防重放） | ✅ | `SessionKey.counter` |
| SEC-04 | **認證加密**（防篡改） | ✅ | Poly1305 標籤 |
| SEC-05 | **密文長度隱藏**（部分） | ⚠️ | ChaCha20 不隱藏長度，但 AEAD 標籤無長度信息 |

### 未滿足（已知限制）

| # | 安全特性 | 狀態 | 風險 | 建議 |
|---|---------|------|------|------|
| SEC-10 | **身份認證**（防 MITM） | ❌ | 🟡 中 | 添加簽名密鑰或預共享密碼 |
| SEC-11 | **前向保密**（PFS） | ❌ | 🟡 中 | 使用 ephemeral X25519（當前是 static） |
| SEC-12 | **密鑰輪換** | ❌ | 🟢 低 | 定期 re-key 或消息計數達閾值 |
| SEC-13 | **密鑰確認**（Key Confirmation） | ❌ | 🟡 中 | DH 後雙方互相驗證 shared secret |
| SEC-14 | **身份綁定** | ❌ | 🟡 中 | 將 PeerId 綁定到 X25519 公鑰 |

### ⚠️ MITM 攻擊場景（當前可被利用）

```
A ──KeyExchange──→ MITM ──KeyExchange──→ B
                   │
         MITM 替換公鑰：
         收到 A.pub → 發送 MITM.pub 給 B
         收到 B.pub → 發送 MITM.pub 給 A
         
結果：MITM 與 A 建立 shared_a，與 B 建立 shared_b
      MITM 可解密 A 的消息 → 用 shared_b 重新加密發給 B
      A 和 B 均不知曉
```

**P0 不要求修復 MITM**（POC 級別），但 **Phase D 前必須解決**。

---

## 六、測試自動化建議

```bash
# 單元測試（已有 6 個）
cargo test --lib

# 示例編譯
cargo build --example encrypted_chat

# CI 完整流水線（建議）
cargo fmt --check && cargo clippy --all-targets && cargo test && cargo build --examples
```

---

## 七、P0 Gate（MVP 出門標準）

**以下全部 PASS 才能 declare P0 done：**

- [ ] AT-01-A: 自動密鑰交換（3 秒內）
- [ ] AT-01-B: 密鑰一致性
- [ ] AT-01-C: 多 Peer 獨立會話
- [ ] AT-02-A: A→B 加密消息
- [ ] AT-02-B: B→A 加密消息
- [ ] AT-02-C: 雙向連續 100 條
- [ ] AT-02-D: UTF-8 中文消息
- [ ] AT-03-A: 第三方不可解密
- [ ] AT-03-B: 密文不含明文
- [ ] AT-04-A: 篡改密文檢測
- [ ] AT-05-A: Nonce 唯一性（1000 條）
- [ ] AT-06-A: 密鑰隨機性
- [ ] AT-06-B: DH 一致性
- [ ] AT-07-A/B/C: 錯誤輸入拒絕
- [ ] AT-08-A: mDNS + 加密
- [ ] AT-08-B: 手動 dial + 加密
- [ ] AT-E01-A: Demo 正常啟動
- [ ] AT-E02-A/B/C: Demo 命令
- [ ] AT-E03-A~G: 雙節點完整流程

**共 19 項 P0 檢查點。**

---

*Bridge 🎯👥 — 安全無小事，驗收無人情。*
*2026-03-28 06:15 CST*
