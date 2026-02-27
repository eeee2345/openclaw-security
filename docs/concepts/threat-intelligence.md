# Threat Intelligence / 威脅情報

> 知道攻擊者是誰、用什麼手法、從哪來，才能有效防禦。

---

## 什麼是威脅情報？

威脅情報是關於已知攻擊者、惡意 IP、惡意網址、惡意程式的結構化資訊。Panguard 會自動查詢這些資料庫來判斷你系統上的活動是否與已知威脅相關。

**你不需要理解這些技術細節。** Guard 會自動處理，Chat 會用人話告訴你結果。

---

## 情報來源

Panguard 整合 5 個公開威脅情報來源：

### abuse.ch 系列

| 來源                                           | 類型            | 說明                                      |
| ---------------------------------------------- | --------------- | ----------------------------------------- |
| [ThreatFox](https://threatfox.abuse.ch)        | IoC（入侵指標） | IP、域名、URL、檔案 hash 的惡意指標資料庫 |
| [URLhaus](https://urlhaus.abuse.ch)            | 惡意 URL        | 惡意軟體散布網址資料庫                    |
| [Feodo Tracker](https://feodotracker.abuse.ch) | C2 伺服器       | 殭屍網路 Command & Control 伺服器追蹤     |

### 其他來源

| 來源                               | 類型    | 說明                             |
| ---------------------------------- | ------- | -------------------------------- |
| [GreyNoise](https://greynoise.io)  | IP 聲譽 | 區分有目標的攻擊和大規模網路掃描 |
| [AbuseIPDB](https://abuseipdb.com) | IP 檢舉 | 社群回報的惡意 IP 資料庫         |

---

## 運作方式

### 自動查詢

Guard 在偵測到可疑活動時自動查詢威脅情報：

```
偵測到可疑 IP 203.0.113.50 連線
       |
       v
  查詢 ThreatFox  -> 已知 C2 伺服器
  查詢 AbuseIPDB  -> 被檢舉 1,247 次
  查詢 GreyNoise  -> 大規模掃描器
       |
       v
  結論：高風險，自動封鎖 + 通知你
```

### Feed 更新

威脅情報 Feed 定期自動更新：

```
ThreatFox     每 6 小時更新
URLhaus       每 6 小時更新
Feodo         每 6 小時更新
GreyNoise     依查詢即時取得
AbuseIPDB     依查詢即時取得
```

### 本地快取

查詢結果會快取在本地，避免重複查詢：

- 快取時間：依來源設定（1-24 小時）
- 快取位置：Guard 資料目錄
- 過期自動清理

---

## 入侵指標（IoC）類型

威脅情報追蹤以下類型的入侵指標：

| 類型      | 說明         | 範例                          |
| --------- | ------------ | ----------------------------- |
| IP 位址   | 已知惡意 IP  | `203.0.113.50`                |
| 域名      | 惡意域名     | `malware.example.com`         |
| URL       | 惡意網址     | `http://evil.com/payload.exe` |
| 檔案 Hash | 惡意檔案指紋 | SHA-256 hash                  |
| Email     | 釣魚郵件地址 | `phish@attacker.com`          |

---

## Threat Cloud — 集體威脅情報

除了公開來源，Panguard 用戶可以透過 Threat Cloud 共享威脅情報：

- 你的 Guard 偵測到新威脅 -> 匿名化上傳到 Threat Cloud
- 其他 Panguard 用戶立即收到更新 -> 防護範圍擴大

```
  你的 Panguard                Threat Cloud              其他用戶的 Panguard
       |                           |                           |
  偵測到新威脅  ──匿名化上傳──>  收集+驗證  ──規則推送──>  提前防護
```

**隱私保證**：上傳的只有威脅指標（IP、hash、模式），不包含你的系統資訊或個人資料。

[Threat Cloud 部署指南 ->](../guides/threat-cloud.md)

---

## 如何查看威脅情報

### Guard 狀態

```bash
panguard guard status
```

會顯示最近的威脅情報匹配：

```
  ── Threat Intelligence ────────────────

  Feeds:        5 active, last update 2h ago
  IoC matched:  3 in last 24h
  Blocked IPs:  12 total
```

### Chat 通知

當威脅情報匹配到你系統上的活動，Chat 會用人話通知你：

**boss 角色收到的通知：**

> 偵測到你的伺服器正在與一個已知的惡意伺服器通訊。
> 該 IP 已被全球 1,247 次檢舉為攻擊來源。
> 已自動封鎖該連線。無需你採取行動。

**developer 角色收到的通知：**

> Threat Intel Match: 203.0.113.50
> Source: AbuseIPDB (confidence: 98%), ThreatFox (tag: C2)
> Action: IP blocked via iptables
> Rule: Auto-response (confidence > 90%)

---

## 相關文件

- [Panguard Guard 使用指南](../guides/guard.md)
- [Threat Cloud 部署指南](../guides/threat-cloud.md)
- [三層 AI 架構](three-layer-ai.md)
