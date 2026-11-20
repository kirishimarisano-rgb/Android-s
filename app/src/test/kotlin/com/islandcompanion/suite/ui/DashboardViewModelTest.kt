package com.islandcompanion.suite.ui

import com.islandcompanion.suite.core.rules.ExecutionSpace
import com.islandcompanion.suite.core.rules.SecurityFeatureModule
import com.islandcompanion.suite.core.rules.SpaceOverrideMode
import com.islandcompanion.suite.space.ProfileOwnerInspector
import com.islandcompanion.suite.space.SpaceDetector
import com.islandcompanion.suite.space.SpaceOverrideRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class DashboardViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun buildFeatureCards_prioritizesNetGuardInWorkProfile() {
        val cards = DashboardViewModel.buildFeatureCards(ExecutionSpace.WORK_PROFILE)

        assertEquals(SecurityFeatureModule.NETGUARD, cards.first().module)
        assertTrue(cards.first().recommended)
        assertTrue(cards.drop(1).none { it.recommended })
    }

    @Test
    fun buildFeatureCards_prioritizesMainlandToolsInMainland() {
        val cards = DashboardViewModel.buildFeatureCards(ExecutionSpace.MAINLAND)

        val recommendedModules = cards.filter { it.recommended }.map { it.module }
        assertEquals(
            listOf(
                SecurityFeatureModule.SANITIZER,
                SecurityFeatureModule.INSPECTOR,
                SecurityFeatureModule.ISLAND_CTRL,
            ),
            recommendedModules,
        )
        assertEquals(SecurityFeatureModule.NETGUARD, cards.last().module)
        assertFalse(cards.last().recommended)
    }

    @Test
    fun updateOverrideMode_switchesEffectiveSpaceAndRecommendedCards() = runTest(testDispatcher) {
        val detector = SpaceDetector(
            inspector = object : ProfileOwnerInspector {
                override fun getActiveAdminPackages(): List<String> = emptyList()
                override fun isProfileOwnerApp(packageName: String): Boolean = false
            },
        )
        val repository = FakeSpaceOverrideRepository()
        val viewModel = DashboardViewModel(detector, repository)

        val collectJob = launch { viewModel.uiState.collect {} }
        advanceUntilIdle()

        assertEquals(ExecutionSpace.MAINLAND, viewModel.uiState.value.effectiveSpace)
        assertFalse(viewModel.uiState.value.isManualOverrideActive)

        viewModel.updateOverrideMode(SpaceOverrideMode.FORCE_WORK_PROFILE)
        advanceUntilIdle()

        assertEquals(ExecutionSpace.WORK_PROFILE, viewModel.uiState.value.effectiveSpace)
        assertTrue(viewModel.uiState.value.isManualOverrideActive)
        assertEquals(SecurityFeatureModule.NETGUARD, viewModel.uiState.value.featureCards.first().module)

        collectJob.cancel()
    }

    private class FakeSpaceOverrideRepository : SpaceOverrideRepository {
        private val state = MutableStateFlow(SpaceOverrideMode.AUTO)
        override val overrideMode: Flow<SpaceOverrideMode> = state
        override suspend fun setOverrideMode(mode: SpaceOverrideMode) {
            state.value = mode
        }
    }
}
