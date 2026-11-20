package com.islandcompanion.suite.di

import android.content.Context
import com.islandcompanion.suite.core.rules.DataStoreNetGuardRulesRepository
import com.islandcompanion.suite.core.rules.NetGuardRulesRepository
import com.islandcompanion.suite.space.AndroidProfileOwnerInspector
import com.islandcompanion.suite.space.DataStoreSpaceOverrideRepository
import com.islandcompanion.suite.space.SpaceDetector
import com.islandcompanion.suite.space.SpaceOverrideRepository

/**
 * 輕量手動依賴注入容器，集中管理 `:app` 與功能模組共用的實例。
 */
class AppContainer(context: Context) {
    private val appContext = context.applicationContext

    /**
     * 安全執行空間偵測器實例。
     */
    val spaceDetector: SpaceDetector = SpaceDetector(
        inspector = AndroidProfileOwnerInspector(appContext),
    )

    /**
     * 本機空間覆寫設定儲存庫實例。
     */
    val spaceOverrideRepository: SpaceOverrideRepository =
        DataStoreSpaceOverrideRepository(appContext)

    /**
     * 本機網路守門員規則與網域黑名單儲存庫實例。
     */
    val netGuardRulesRepository: NetGuardRulesRepository =
        DataStoreNetGuardRulesRepository(appContext)
}
