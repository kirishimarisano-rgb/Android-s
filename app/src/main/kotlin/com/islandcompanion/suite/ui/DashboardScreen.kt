package com.islandcompanion.suite.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.FactCheck
import androidx.compose.material.icons.outlined.AcUnit
import androidx.compose.material.icons.outlined.CleaningServices
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.VpnLock
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.islandcompanion.suite.core.rules.ExecutionSpace
import com.islandcompanion.suite.core.rules.SecurityFeatureModule
import com.islandcompanion.suite.core.ui.components.FeatureModuleCard
import com.islandcompanion.suite.core.ui.components.SpaceStatusBadge

/**
 * 中央儀表板畫面：頂部呈現目前空間狀態標籤，並依空間模式自動高亮推薦模組卡片。
 */
@Composable
fun DashboardScreen(
    uiState: DashboardUiState,
    onSelectFeature: (SecurityFeatureModule) -> Unit,
    modifier: Modifier = Modifier,
) {
    val isWorkProfile = uiState.effectiveSpace == ExecutionSpace.WORK_PROFILE
    val recommendedCards = uiState.featureCards.filter { it.recommended }
    val secondaryCards = uiState.featureCards.filterNot { it.recommended }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "space_status_badge") {
            SpaceStatusBadge(
                label = if (isWorkProfile) "Island 沙盒模式" else "主空間安檢模式",
                subtitle = if (isWorkProfile) {
                    "偵測為工作設定檔環境，已優先高亮本機網路守門員。"
                } else {
                    "偵測為主空間環境，已優先高亮隱私淨化、APK 體檢與凍結控制。"
                },
                icon = if (isWorkProfile) Icons.Outlined.Security else Icons.Outlined.Shield,
                isWorkProfile = isWorkProfile,
                isOverridden = uiState.isManualOverrideActive,
            )
        }

        item(key = "recommended_header") {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "推薦使用模組",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }

        items(
            items = recommendedCards,
            key = { it.module.name },
        ) { card ->
            FeatureModuleCard(
                title = card.title,
                description = card.description,
                badgeText = card.badgeText,
                icon = card.module.toIcon(),
                highlighted = true,
                onClick = { onSelectFeature(card.module) },
            )
        }

        if (secondaryCards.isNotEmpty()) {
            item(key = "secondary_header") {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "其他可用模組",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            items(
                items = secondaryCards,
                key = { it.module.name },
            ) { card ->
                FeatureModuleCard(
                    title = card.title,
                    description = card.description,
                    badgeText = card.badgeText,
                    icon = card.module.toIcon(),
                    highlighted = false,
                    onClick = { onSelectFeature(card.module) },
                )
            }
        }
    }
}

private fun SecurityFeatureModule.toIcon(): ImageVector = when (this) {
    SecurityFeatureModule.NETGUARD -> Icons.Outlined.VpnLock
    SecurityFeatureModule.SANITIZER -> Icons.Outlined.CleaningServices
    SecurityFeatureModule.INSPECTOR -> Icons.AutoMirrored.Outlined.FactCheck
    SecurityFeatureModule.ISLAND_CTRL -> Icons.Outlined.AcUnit
}
