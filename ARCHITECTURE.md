# Project Constitution: Island Companion Security Suite

## 1. 專案目標
這是一個搭配 Android 原生 Work Profile（Island / Insular）使用的「單一中央管理安全增強 App」。
採用「單一 APK、雙空間雙重角色」設計：安裝在主空間（Mainland）與 Island 內時，會自動偵測所處空間並切換預設顯示的儀表板模組。

## 2. 嚴格安全紅線（絕對禁止）
- **禁止**要求 Root、Magisk、LSPosed、Shizuku 或解鎖 Bootloader。
- **禁止**申請 `Device Owner`、`AccessibilityService`（無障礙服務）或 `QUERY_ALL_PACKAGES`（除非特定模組經使用者明確同意且無替代方案）。
- **禁止**實作 HTTPS MITM 中間人解密或要求安裝自簽 Root CA 憑證。網路過濾與防洩漏嚴格停留在 **IP + DNS + TLS SNI** 層級。
- **禁止**將任何使用者流量、日誌或檔案上傳至外部伺服器（除非使用者明確開啟自訂的 SOCKS5 上游代理）。
- 嚴格遵循最小權限原則；所有設定與規則皆存放於本機儲存空間。

## 3. 技術棧鎖定
- 語言：Kotlin（嚴禁使用 Java 寫新邏輯）
- UI：Jetpack Compose + Material 3（深色模式友善、簡潔工具風格）
- 建置工具：Gradle Kotlin DSL (`.kts`) + Version Catalog (`gradle/libs.versions.toml`)
- SDK 版本：`minSdk = 26`, `compileSdk = 35`, `targetSdk = 35`, Java/JVM Target 17
- 架構：MVVM + Clean Architecture + 單向資料流（StateFlow）
- 依賴注入：Hilt 或純手動 DI（優先保持輕量、少魔法）

## 4. 多模組目錄規劃
- `:app`：程式進入點、底部導航、空間偵測器（判斷 Mainland vs. Work Profile）
- `:core-ui`：共用主題、元件、卡片樣式
- `:core-rules`：共用資料模型、規則儲存（Room 或 DataStore）、JSON 規則匯入／匯出
- `:feature-netguard`：本機 `VpnService` 監控、網域／DNS／SNI 封鎖、區網與 STUN 隔離、SOCKS5 上游轉發
- `:feature-sanitizer`：Share Target 圖片去 EXIF、網址追蹤參數清除與短網址檢查
- `:feature-inspector`：安裝前 APK 靜態解析（權限風險與常見追蹤 SDK 偵測）
- `:feature-island-ctrl`：串接 Island Open API 的一鍵凍結／排程凍結助手

## 5. 開發紀律
- 每次只實作使用者指定的單一里程碑，不要提前偷寫後續模組的業務邏輯。
- 避免使用需要系統特權的隱藏 API（例如偵測 Work Profile 時**禁止**呼叫會觸發 `SecurityException` 的 `UserManager.isManagedProfile()`，請改用 `DevicePolicyManager.activeAdmins` 搭配 `isProfileOwnerApp()` 判斷，並提供手動切換開關作為備援）。
- 所有公開 API 與權限申請必須附上簡短註解說明用途。
- 每次修改後必須確保 `./gradlew assembleDebug` 與基礎單元測試可通過。