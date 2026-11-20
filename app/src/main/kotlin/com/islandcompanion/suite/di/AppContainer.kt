package com.islandcompanion.suite.di

import android.content.Context
import com.islandcompanion.suite.space.AndroidProfileOwnerInspector
import com.islandcompanion.suite.space.DataStoreSpaceOverrideRepository
import com.islandcompanion.suite.space.SpaceDetector
import com.islandcompanion.suite.space.SpaceOverrideRepository

/**
 * 輕量手動依賴注入容器，集中管理 `:app` 模組共用的實例。
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
}
