package com.islandcompanion.suite.feature.sanitizer

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CleaningServices
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.islandcompanion.suite.core.ui.components.PlaceholderFeatureScreen

/**
 * 隱私淨化（:feature-sanitizer）的佔位畫面。
 * 本階段僅提供空殼介面，圖片去 EXIF 與網址追蹤參數清除將於後續里程碑實作。
 */
@Composable
fun SanitizerPlaceholderScreen(modifier: Modifier = Modifier) {
    PlaceholderFeatureScreen(
        title = "隱私淨化",
        milestoneHint = "模組佔位 • 尚未啟用淨化引擎",
        description = "預計於後續里程碑提供 Share Target 圖片 EXIF 元資料清除、網址追蹤參數剝除與短網址安全檢查，所有處理皆在本機完成。",
        icon = Icons.Outlined.CleaningServices,
        modifier = modifier,
    )
}
