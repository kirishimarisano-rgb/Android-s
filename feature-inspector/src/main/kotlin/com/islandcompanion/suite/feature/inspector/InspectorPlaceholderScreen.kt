package com.islandcompanion.suite.feature.inspector

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.FactCheck
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.islandcompanion.suite.core.ui.components.PlaceholderFeatureScreen

/**
 * APK 體檢（:feature-inspector）的佔位畫面。
 * 本階段僅提供空殼介面，安裝前 APK 靜態解析與追蹤 SDK 偵測將於後續里程碑實作。
 */
@Composable
fun InspectorPlaceholderScreen(modifier: Modifier = Modifier) {
    PlaceholderFeatureScreen(
        title = "APK 體檢",
        milestoneHint = "模組佔位 • 尚未啟用靜態解析",
        description = "預計於後續里程碑提供安裝前本機 APK 靜態分析，檢視高風險權限組合與常見廣告／追蹤 SDK 特徵。",
        icon = Icons.AutoMirrored.Outlined.FactCheck,
        modifier = modifier,
    )
}
