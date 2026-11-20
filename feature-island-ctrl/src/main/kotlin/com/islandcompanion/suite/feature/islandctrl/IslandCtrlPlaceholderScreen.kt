package com.islandcompanion.suite.feature.islandctrl

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AcUnit
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.islandcompanion.suite.core.ui.components.PlaceholderFeatureScreen

/**
 * 凍結控制（:feature-island-ctrl）的佔位畫面。
 * 本階段僅提供空殼介面，Island Open API 一鍵凍結與排程凍結將於後續里程碑實作。
 */
@Composable
fun IslandCtrlPlaceholderScreen(modifier: Modifier = Modifier) {
    PlaceholderFeatureScreen(
        title = "凍結控制",
        milestoneHint = "模組佔位 • 尚未串接 Island Open API",
        description = "預計於後續里程碑串接 Island Open API，提供沙盒內應用程式一鍵凍結與排程自動休眠助手。",
        icon = Icons.Outlined.AcUnit,
        modifier = modifier,
    )
}
