# rhb-reflex

RHB Reflex App（Promon SHIELD 加固）逆向分析项目：从壳层解包、检测器定位，到
DuitNow 收款二维码业务协议的全链路复现。

> 仅用于**自有商户账号**的授权测试与安全研究，不得用于任何非授权账户。

---

## 项目简介

目标 App：`com.rhb.reflex.bank`（Promon SHIELD 壳，`libShieldSDK.so` +
`libreflex_bank.so`）。本项目完整复盘了以下逆向链：

1. **壳层自解包**：`libreflex_bank.so` 代码块级加密（ChaCha8，rounds=8），
   `mprotect` 写执行窗口 + 晚期内存 dump 还原全部 RX 区域；
2. **Java token 解密**：`cyyh.n.d(int)` 两级查表（key = id >> 4，slot = id & 0xF），
   全量导出 34,712 个 token 明文；
3. **运行时字符串取证**：`/proc/self/smaps` 等关键路径由 SIMD 现场构造，
   syscall 实参 + FP 链回溯 + 公共复制点聚合三层取证；
4. **检测器定位**：从外部威胁码 `"00"` 回溯 W22 状态机，定位
   stage/detail `0x17` → `sub_26C484` 的 boot-state 与 Android Key Attestation
   一致性检查；
5. **协议复现**：登录 → 令牌轮换 → 生成 DuitNow 动态二维码的完整 API 流程，
   RSA-1024 / PKCS1v15 密码加密与 HMAC-SHA256 请求签名逐字段复算，TLS/JA3
   指纹模拟。

配套分析文档分三章（字符串解密 / syscall trace / SO 静态分析）与一篇完整逆向文章，随系列更新逐步发布。

---

## 关键技术点

| 模块 | 要点 |
|---|---|
| 自解包 | `0x642C38 → 0x642F1C → 0x643810 → 0x65A500 → 0x659CCC`，`expand 32-byte k` 常量，nonce `0x92574` |
| Token 查表 | `0x4D3368 → 0x389FD4 → 0x38A3D0 → 0x38AFE4 → 0x4C1D08(NewStringUTF)` |
| 运行时字符串 | 24 字节 string 容器（data/cap/len），公共复制点 `sub_171D88`（1,697 个调用点） |
| 状态机 | `sub_1B1EC8`（TST/CSEL 分支）→ detail `0x17` → `sub_26C484` |
| Attestation | `RootOfTrustASN1` / `KeyDescriptionASN1` schema → `0x6EA450` 注册表 → `sub_50FC24` |
| 请求签名 | `hmac = HMAC-SHA256(key=jti+apiKey, data=base64("bearer "+token)+body)` |
| TLS 指纹 | `tls-client` 预设 `okhttp4_android_13`，与手机 ClientHello 一致 |

---

## 安全合规声明

1. 本项目全部工作针对**本人/客户自有商户账号**（需自己的 userId 与登录密码）；
2. 对非授权目标进行逆向、绕过安全检测在多数法域可能构成违法；
3. 仓库内所有凭据、账号、密钥均以脱敏形式出现；
4. 本项目仅用于技术交流与授权测试，任何滥用后果由使用者自行承担。

---

## 联系方式

付费咨询（仅接授权项目）：加固 App 协议逆向 / 签名算法还原 / 风控参数定位 /
数据采集架构设计。不接受灰黑产需求。

| 渠道 | 账号 |
|---|---|
| 微信 | `__int64` |
| QQ | `1415662711` |
| Telegram | [@luotron](https://t.me/luotron) |

---

*技术无罪，行为有边界。*
