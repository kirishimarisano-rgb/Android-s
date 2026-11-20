package com.islandcompanion.suite

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.viewmodel.compose.viewModel
import com.islandcompanion.suite.core.ui.theme.IslandCompanionTheme
import com.islandcompanion.suite.ui.DashboardViewModel
import com.islandcompanion.suite.ui.IslandCompanionApp

/**
 * 單一主 Activity，承載 Jetpack Compose 中央儀表板與各功能分頁。
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val appContainer = (application as IslandCompanionApplication).appContainer

        setContent {
            IslandCompanionTheme {
                val dashboardViewModel: DashboardViewModel = viewModel(
                    factory = DashboardViewModel.provideFactory(
                        spaceDetector = appContainer.spaceDetector,
                        spaceOverrideRepository = appContainer.spaceOverrideRepository,
                    ),
                )
                IslandCompanionApp(viewModel = dashboardViewModel)
            }
        }
    }
}
