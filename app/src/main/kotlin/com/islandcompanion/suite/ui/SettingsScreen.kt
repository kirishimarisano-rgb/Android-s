package com.islandcompanion.suite.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.islandcompanion.suite.core.rules.ExecutionSpace
import com.islandcompanion.suite.core.rules.SpaceOverrideMode

/**
 * 設定畫面：提供手動覆寫執行空間角色模式的選項，並顯示自動偵測診斷資訊。
 */
@Composable
fun SettingsScreen(
    uiState: DashboardUiState,
    onSelectOverrideMode: (SpaceOverrideMode) -> Unit,
    onRefreshDetection: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "執行空間角色設定",
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onBackground,
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant,
            ),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
                    .selectableGroup(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "角色模式覆寫（測試與備援用）",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = "預設會透過 DevicePolicyManager 安全偵測是否位於 Work Profile（Island）。您也可以手動指定顯示角色以測試雙空間儀表板。",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(4.dp))

                OverrideOptionRow(
                    title = "自動偵測（推薦）",
                    subtitle = "依系統 Profile Owner 狀態自動切換主空間與 Island 模式",
                    selected = uiState.overrideMode == SpaceOverrideMode.AUTO,
                    onClick = { onSelectOverrideMode(SpaceOverrideMode.AUTO) },
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
                OverrideOptionRow(
                    title = "強制主空間安檢模式（Mainland）",
                    subtitle = "優先高亮隱私淨化、APK 體檢與凍結控制",
                    selected = uiState.overrideMode == SpaceOverrideMode.FORCE_MAINLAND,
                    onClick = { onSelectOverrideMode(SpaceOverrideMode.FORCE_MAINLAND) },
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
                OverrideOptionRow(
                    title = "強制 Island 沙盒模式（Work Profile）",
                    subtitle = "優先高亮網路守門員",
                    selected = uiState.overrideMode == SpaceOverrideMode.FORCE_WORK_PROFILE,
                    onClick = { onSelectOverrideMode(SpaceOverrideMode.FORCE_WORK_PROFILE) },
                )
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface,
            ),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "空間偵測診斷資訊",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                DiagnosticRow(
                    label = "系統自動偵測結果",
                    value = uiState.detectedSpace.toDisplayName(),
                )
                DiagnosticRow(
                    label = "目前生效模式",
                    value = uiState.effectiveSpace.toDisplayName(),
                )
                DiagnosticRow(
                    label = "偵測到的 Profile Owner",
                    value = uiState.profileOwnerPackage ?: "無（位於主空間）",
                )
                Spacer(modifier = Modifier.height(4.dp))
                OutlinedButton(
                    onClick = onRefreshDetection,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(text = "重新偵測執行空間")
                }
            }
        }
    }
}

@Composable
private fun OverrideOptionRow(
    title: String,
    subtitle: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(
                selected = selected,
                onClick = onClick,
                role = Role.RadioButton,
            )
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        RadioButton(
            selected = selected,
            onClick = null,
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun DiagnosticRow(
    label: String,
    value: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

private fun ExecutionSpace.toDisplayName(): String = when (this) {
    ExecutionSpace.MAINLAND -> "主空間安檢模式（Mainland）"
    ExecutionSpace.WORK_PROFILE -> "Island 沙盒模式（Work Profile）"
}
