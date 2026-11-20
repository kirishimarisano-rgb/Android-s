package com.islandcompanion.suite.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.islandcompanion.suite.core.rules.ExecutionSpace
import com.islandcompanion.suite.core.rules.SecurityFeatureModule
import com.islandcompanion.suite.core.rules.SpaceOverrideMode
import com.islandcompanion.suite.space.SpaceDetectionResult
import com.islandcompanion.suite.space.SpaceDetector
import com.islandcompanion.suite.space.SpaceOverrideRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * 單一儀表板功能卡片的呈現狀態。
 */
data class DashboardFeatureCardState(
    val module: SecurityFeatureModule,
    val title: String,
    val description: String,
    val recommended: Boolean,
    val badgeText: String?,
)

/**
 * 中央儀表板與設定頁共用的單向資料流狀態模型。
 */
data class DashboardUiState(
    val detectedSpace: ExecutionSpace = ExecutionSpace.MAINLAND,
    val profileOwnerPackage: String? = null,
    val overrideMode: SpaceOverrideMode = SpaceOverrideMode.AUTO,
    val effectiveSpace: ExecutionSpace = ExecutionSpace.MAINLAND,
    val featureCards: List<DashboardFeatureCardState> = emptyList(),
) {
    /**
     * 目前生效角色是否透過設定頁手動覆寫。
     */
    val isManualOverrideActive: Boolean
        get() = overrideMode != SpaceOverrideMode.AUTO
}

/**
 * 中央儀表板與空間角色切換的 ViewModel，透過 [StateFlow] 維持單向資料流。
 */
class DashboardViewModel(
    private val spaceDetector: SpaceDetector,
    private val spaceOverrideRepository: SpaceOverrideRepository,
) : ViewModel() {

    private val detectionResultFlow = MutableStateFlow(spaceDetector.detect())

    /**
     * 儀表板即時狀態，隨空間偵測與手動覆寫設定自動更新並重新排序推薦卡片。
     */
    val uiState: StateFlow<DashboardUiState> = combine(
        detectionResultFlow,
        spaceOverrideRepository.overrideMode,
    ) { detection, overrideMode ->
        buildUiState(detection, overrideMode)
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = buildUiState(detectionResultFlow.value, SpaceOverrideMode.AUTO),
    )

    /**
     * 重新執行一次系統空間偵測。
     */
    fun refreshSpaceDetection() {
        detectionResultFlow.value = spaceDetector.detect()
    }

    /**
     * 更新手動覆寫模式並寫入本機儲存。
     */
    fun updateOverrideMode(mode: SpaceOverrideMode) {
        viewModelScope.launch {
            spaceOverrideRepository.setOverrideMode(mode)
        }
    }

    private fun buildUiState(
        detection: SpaceDetectionResult,
        overrideMode: SpaceOverrideMode,
    ): DashboardUiState {
        val effectiveSpace = spaceDetector.resolveEffectiveSpace(
            detectedSpace = detection.detectedSpace,
            overrideMode = overrideMode,
        )
        return DashboardUiState(
            detectedSpace = detection.detectedSpace,
            profileOwnerPackage = detection.profileOwnerPackage,
            overrideMode = overrideMode,
            effectiveSpace = effectiveSpace,
            featureCards = buildFeatureCards(effectiveSpace),
        )
    }

    companion object {
        /**
         * 根據目前生效的執行空間，產生並排序功能卡片清單：
         * - [ExecutionSpace.WORK_PROFILE]（Island 沙盒模式）：優先高亮網路守門員。
         * - [ExecutionSpace.MAINLAND]（主空間安檢模式）：優先高亮隱私淨化、APK 體檢與凍結控制。
         */
        fun buildFeatureCards(space: ExecutionSpace): List<DashboardFeatureCardState> {
            val netguard = DashboardFeatureCardState(
                module = SecurityFeatureModule.NETGUARD,
                title = "網路守門員",
                description = "本機 VpnService 監控、IP / DNS / TLS SNI 封鎖、區網與 STUN 隔離。",
                recommended = space == ExecutionSpace.WORK_PROFILE,
                badgeText = if (space == ExecutionSpace.WORK_PROFILE) "沙盒主力" else null,
            )
            val sanitizer = DashboardFeatureCardState(
                module = SecurityFeatureModule.SANITIZER,
                title = "隱私淨化",
                description = "分享前去除圖片 EXIF 資訊、清除網址追蹤參數與短網址檢查。",
                recommended = space == ExecutionSpace.MAINLAND,
                badgeText = if (space == ExecutionSpace.MAINLAND) "主空間推薦" else null,
            )
            val inspector = DashboardFeatureCardState(
                module = SecurityFeatureModule.INSPECTOR,
                title = "APK 體檢",
                description = "安裝前靜態解析 APK 權限風險與常見追蹤 SDK 特徵。",
                recommended = space == ExecutionSpace.MAINLAND,
                badgeText = if (space == ExecutionSpace.MAINLAND) "主空間推薦" else null,
            )
            val islandCtrl = DashboardFeatureCardState(
                module = SecurityFeatureModule.ISLAND_CTRL,
                title = "凍結控制",
                description = "透過 Island Open API 一鍵凍結與排程管理沙盒應用程式。",
                recommended = space == ExecutionSpace.MAINLAND,
                badgeText = if (space == ExecutionSpace.MAINLAND) "主空間推薦" else null,
            )

            return when (space) {
                ExecutionSpace.WORK_PROFILE -> listOf(netguard, sanitizer, inspector, islandCtrl)
                ExecutionSpace.MAINLAND -> listOf(sanitizer, inspector, islandCtrl, netguard)
            }
        }

        /**
         * 手動 DI 用的 ViewModelFactory。
         */
        fun provideFactory(
            spaceDetector: SpaceDetector,
            spaceOverrideRepository: SpaceOverrideRepository,
        ): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                require(modelClass.isAssignableFrom(DashboardViewModel::class.java)) {
                    "Unknown ViewModel class: ${modelClass.name}"
                }
                return DashboardViewModel(spaceDetector, spaceOverrideRepository) as T
            }
        }
    }
}
