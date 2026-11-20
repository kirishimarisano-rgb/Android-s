package com.islandcompanion.suite.feature.netguard

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.VpnLock
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.islandcompanion.suite.core.ui.components.PlaceholderFeatureScreen

/**
 * 網路守門員（:feature-netguard）的佔位畫面。
 * 本階段僅提供空殼介面，本機 VpnService 與 IP/DNS/SNI 過濾將於後續里程碑實作。
 */
@Composable
fun NetGuardPlaceholderScreen(modifier: Modifier = Modifier) {
    PlaceholderFeatureScreen(
        title = "網路守門員",
        milestoneHint = "模組佔位 • 尚未啟用底層引擎",
        description = "預計於後續里程碑提供免 Root 本機 VpnService 流量監控、IP / DNS / TLS SNI 網域封鎖、區網與 STUN 隔離，以及可選的 SOCKS5 上游轉發。",
        icon = Icons.Outlined.VpnLock,
        modifier = modifier,
    )
}
