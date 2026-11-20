package com.islandcompanion.suite.core.rules

/**
 * 代表目前 App 所執行的 Android 空間角色。
 *
 * - [MAINLAND]：主空間（個人空間），優先提供隱私淨化、APK 體檢與 Island 凍結控制。
 * - [WORK_PROFILE]：工作設定檔（Island / Insular 沙盒空間），優先提供本機網路守門員。
 */
enum class ExecutionSpace {
    MAINLAND,
    WORK_PROFILE,
}

/**
 * 允許使用者在設定頁手動覆寫執行空間角色的模式，主要用於測試與備援。
 */
enum class SpaceOverrideMode {
    AUTO,
    FORCE_MAINLAND,
    FORCE_WORK_PROFILE,
}

/**
 * 四大核心安全功能模組識別符，用於儀表板排序與底部導航切換。
 */
enum class SecurityFeatureModule {
    NETGUARD,
    SANITIZER,
    INSPECTOR,
    ISLAND_CTRL,
}
