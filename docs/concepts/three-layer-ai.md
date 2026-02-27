# Three-Layer AI Funnel / 三層 AI 漏斗架構

> 90% 的安全事件用規則引擎在 1 毫秒內處理，只有最複雜的 3% 才動用雲端 AI。

---

## 為什麼需要三層架構？

把每個安全事件都丟給 AI 分析，會產生三個問題：

1. **太慢** — AI 推理需要數秒，攻擊不會等你
2. **太貴** — 每台機器每天產生數千個事件，token 成本失控
3. **不可靠** — API 斷線 = 防護中斷

三層漏斗的設計原則：**大多數攻擊都有已知模式，只有真正未知的威脅才需要 AI 深度推理。**

---

## 架構圖

```
  安全事件流入
       |
       v
  +-----------+
  | Layer 1   |  Sigma / YARA 規則引擎
  | 90% 事件  |  延遲 < 1ms | 成本 = 零
  +-----------+
       |
    未匹配 (10%)
       |
       v
  +-----------+
  | Layer 2   |  本地 AI (Ollama)
  | 7% 事件   |  延遲 < 5s | 成本 = 零（本機）
  +-----------+
       |
    需要更深分析 (3%)
       |
       v
  +-----------+
  | Layer 3   |  雲端 AI
  | 3% 事件   |  延遲 < 30s | 成本極低
  +-----------+
```

---

## Layer 1 — 規則引擎（90%）

處理所有已知攻擊模式，零延遲、零成本。

### Sigma 規則

Sigma 是安全社群的標準規則格式。Panguard Guard 內建 42 條規則，覆蓋常見攻擊模式：

```yaml
title: Suspicious SSH Brute Force
logsource:
  category: network
  product: any
detection:
  selection:
    destination_port: 22
    action: blocked
  condition: selection
level: high
```

支援的 Sigma 功能：

- 布林邏輯：`AND`、`OR`、`NOT`
- 聚合表達式：`1 of them`、`all of them`、`1 of selection*`
- 比對修飾符：`|contains`、`|startswith`、`|endswith`、`|re`
- 數值比較：`|gt`、`|gte`、`|lt`、`|lte`
- 網路比對：`|cidr`（IP 範圍匹配）
- 萬用字元：`*`、`?`
- 括號群組：`(sel_a OR sel_b) AND NOT filter`

### YARA 規則

用於檔案層級的惡意程式偵測：

```yara
rule SuspiciousScript {
  strings:
    $cmd = "rm -rf /" nocase
    $wget = "wget" nocase
  condition:
    any of them
}
```

Panguard 支援原生 YARA 引擎，若系統未安裝 YARA 則自動降級為 regex fallback。

---

## Layer 2 — 本地 AI（7%）

當事件不匹配任何已知規則，但行為可疑時，交由本地 AI 模型分析。

- 使用 [Ollama](https://ollama.ai) 在本機運行
- 不需要網路連線
- 不產生 API 費用
- 推理延遲約 3-5 秒

**適用環境**：伺服器（VPS、雲端主機）。桌機/筆電環境會跳過此層，避免搶占使用者資源。

```
伺服器環境：Layer 1 (90%) -> Layer 2 (7%) -> Layer 3 (3%)
桌機環境：  Layer 1 (90%) -> Layer 3 (5-8%)（跳過 Layer 2）
```

---

## Layer 3 — 雲端 AI（3%）

最複雜的未知威脅，由雲端 AI 進行完整的動態推理。

- 完整上下文分析
- 跨事件關聯
- 攻擊鏈推理
- 修復建議產生

即使雲端 AI 不可用（網路中斷、token 用完），Layer 1 規則引擎仍持續運作。**防護永不中斷。**

---

## 降級保護

三層架構的關鍵設計：任何一層失效，上一層自動接管。

| 情況           | 降級行為             |
| -------------- | -------------------- |
| 雲端 AI 不可用 | Layer 2 本地 AI 接管 |
| Ollama 未安裝  | Layer 1 規則引擎接管 |
| 規則檔損壞     | 內建預設規則啟用     |

**Panguard 永遠有防護，只是精確度不同。**

---

## 相關文件

- [Sigma 規則撰寫指南](../reference/sigma-rules.md)
- [YARA 規則撰寫指南](../reference/yara-rules.md)
- [Panguard Guard 使用指南](../guides/guard.md)
