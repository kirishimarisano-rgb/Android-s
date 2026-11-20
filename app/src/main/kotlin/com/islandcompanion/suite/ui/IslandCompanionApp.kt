package com.islandcompanion.suite.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.FactCheck
import androidx.compose.material.icons.outlined.AcUnit
import androidx.compose.material.icons.outlined.CleaningServices
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.VpnLock
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.islandcompanion.suite.core.rules.SecurityFeatureModule
import com.islandcompanion.suite.feature.inspector.InspectorPlaceholderScreen
import com.islandcompanion.suite.feature.islandctrl.IslandCtrlPlaceholderScreen
import com.islandcompanion.suite.feature.netguard.NetGuardPlaceholderScreen
import com.islandcompanion.suite.feature.sanitizer.SanitizerPlaceholderScreen

private enum class TopLevelTab(
    val label: String,
    val icon: ImageVector,
) {
    DASHBOARD("總覽", Icons.Outlined.Dashboard),
    NETGUARD("守門員", Icons.Outlined.VpnLock),
    SANITIZER("淨化", Icons.Outlined.CleaningServices),
    INSPECTOR("體檢", Icons.AutoMirrored.Outlined.FactCheck),
    ISLAND_CTRL("凍結", Icons.Outlined.AcUnit),
}

/**
 * Island Companion Security Suite 根介面容器，負責頂部標題列、底部五分頁導航與設定頁切換。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IslandCompanionApp(
    viewModel: DashboardViewModel,
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    var currentTab by rememberSaveable { mutableStateOf(TopLevelTab.DASHBOARD) }
    var showSettings by rememberSaveable { mutableStateOf(false) }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = if (showSettings) {
                            "設定"
                        } else {
                            when (currentTab) {
                                TopLevelTab.DASHBOARD -> "Island Companion"
                                TopLevelTab.NETGUARD -> "網路守門員"
                                TopLevelTab.SANITIZER -> "隱私淨化"
                                TopLevelTab.INSPECTOR -> "APK 體檢"
                                TopLevelTab.ISLAND_CTRL -> "凍結控制"
                            }
                        },
                    )
                },
                navigationIcon = {
                    if (showSettings) {
                        IconButton(onClick = { showSettings = false }) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Outlined.ArrowBack,
                                contentDescription = "返回",
                            )
                        }
                    }
                },
                actions = {
                    if (!showSettings) {
                        IconButton(onClick = { showSettings = true }) {
                            Icon(
                                imageVector = Icons.Outlined.Settings,
                                contentDescription = "設定",
                            )
                        }
                    }
                },
            )
        },
        bottomBar = {
            if (!showSettings) {
                NavigationBar {
                    TopLevelTab.entries.forEach { tab ->
                        NavigationBarItem(
                            selected = currentTab == tab,
                            onClick = { currentTab = tab },
                            icon = {
                                Icon(
                                    imageVector = tab.icon,
                                    contentDescription = tab.label,
                                )
                            },
                            label = { Text(text = tab.label) },
                        )
                    }
                }
            }
        },
    ) { innerPadding ->
        val contentModifier = Modifier.padding(innerPadding)
        if (showSettings) {
            SettingsScreen(
                uiState = uiState,
                onSelectOverrideMode = viewModel::updateOverrideMode,
                onRefreshDetection = viewModel::refreshSpaceDetection,
                modifier = contentModifier,
            )
        } else {
            when (currentTab) {
                TopLevelTab.DASHBOARD -> DashboardScreen(
                    uiState = uiState,
                    onSelectFeature = { feature ->
                        currentTab = when (feature) {
                            SecurityFeatureModule.NETGUARD -> TopLevelTab.NETGUARD
                            SecurityFeatureModule.SANITIZER -> TopLevelTab.SANITIZER
                            SecurityFeatureModule.INSPECTOR -> TopLevelTab.INSPECTOR
                            SecurityFeatureModule.ISLAND_CTRL -> TopLevelTab.ISLAND_CTRL
                        }
                    },
                    modifier = contentModifier,
                )

                TopLevelTab.NETGUARD -> NetGuardPlaceholderScreen(modifier = contentModifier)
                TopLevelTab.SANITIZER -> SanitizerPlaceholderScreen(modifier = contentModifier)
                TopLevelTab.INSPECTOR -> InspectorPlaceholderScreen(modifier = contentModifier)
                TopLevelTab.ISLAND_CTRL -> IslandCtrlPlaceholderScreen(modifier = contentModifier)
            }
        }
    }
}
