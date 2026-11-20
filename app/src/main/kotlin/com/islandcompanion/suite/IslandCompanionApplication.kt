package com.islandcompanion.suite

import android.app.Application
import com.islandcompanion.suite.di.AppContainer

/**
 * 應用程式進入點，負責初始化輕量手動 DI 容器 [AppContainer]。
 */
class IslandCompanionApplication : Application() {
    /**
     * 全域依賴容器，供 Activity 與 ViewModelFactory 取得服務實例。
     */
    lateinit var appContainer: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        appContainer = AppContainer(this)
    }
}
