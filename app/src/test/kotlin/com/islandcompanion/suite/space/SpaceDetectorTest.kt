package com.islandcompanion.suite.space

import com.islandcompanion.suite.core.rules.ExecutionSpace
import com.islandcompanion.suite.core.rules.SpaceOverrideMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SpaceDetectorTest {

    @Test
    fun detect_returnsWorkProfile_whenActiveAdminIsProfileOwner() {
        val inspector = FakeProfileOwnerInspector(
            activeAdmins = listOf("com.oasisfeng.island", "com.example.other"),
            profileOwners = setOf("com.oasisfeng.island"),
        )
        val detector = SpaceDetector(inspector)

        val result = detector.detect()

        assertEquals(ExecutionSpace.WORK_PROFILE, result.detectedSpace)
        assertEquals("com.oasisfeng.island", result.profileOwnerPackage)
    }

    @Test
    fun detect_returnsMainland_whenNoActiveAdminIsProfileOwner() {
        val inspector = FakeProfileOwnerInspector(
            activeAdmins = listOf("com.example.deviceadmin"),
            profileOwners = emptySet(),
        )
        val detector = SpaceDetector(inspector)

        val result = detector.detect()

        assertEquals(ExecutionSpace.MAINLAND, result.detectedSpace)
        assertNull(result.profileOwnerPackage)
    }

    @Test
    fun detect_returnsMainland_whenActiveAdminsIsEmpty() {
        val inspector = FakeProfileOwnerInspector(
            activeAdmins = emptyList(),
            profileOwners = emptySet(),
        )
        val detector = SpaceDetector(inspector)

        val result = detector.detect()

        assertEquals(ExecutionSpace.MAINLAND, result.detectedSpace)
        assertNull(result.profileOwnerPackage)
    }

    @Test
    fun detect_fallsBackToMainland_whenInspectorThrowsSecurityException() {
        val failingInspector = object : ProfileOwnerInspector {
            override fun getActiveAdminPackages(): List<String> {
                throw SecurityException("Simulated restriction")
            }

            override fun isProfileOwnerApp(packageName: String): Boolean = false
        }
        val detector = SpaceDetector(failingInspector)

        val result = detector.detect()

        assertEquals(ExecutionSpace.MAINLAND, result.detectedSpace)
        assertNull(result.profileOwnerPackage)
    }

    @Test
    fun resolveEffectiveSpace_appliesManualOverrideModes() {
        val detector = SpaceDetector(FakeProfileOwnerInspector(emptyList(), emptySet()))

        assertEquals(
            ExecutionSpace.MAINLAND,
            detector.resolveEffectiveSpace(ExecutionSpace.MAINLAND, SpaceOverrideMode.AUTO),
        )
        assertEquals(
            ExecutionSpace.WORK_PROFILE,
            detector.resolveEffectiveSpace(ExecutionSpace.WORK_PROFILE, SpaceOverrideMode.AUTO),
        )
        assertEquals(
            ExecutionSpace.WORK_PROFILE,
            detector.resolveEffectiveSpace(ExecutionSpace.MAINLAND, SpaceOverrideMode.FORCE_WORK_PROFILE),
        )
        assertEquals(
            ExecutionSpace.MAINLAND,
            detector.resolveEffectiveSpace(ExecutionSpace.WORK_PROFILE, SpaceOverrideMode.FORCE_MAINLAND),
        )
    }

    private class FakeProfileOwnerInspector(
        private val activeAdmins: List<String>,
        private val profileOwners: Set<String>,
    ) : ProfileOwnerInspector {
        override fun getActiveAdminPackages(): List<String> = activeAdmins
        override fun isProfileOwnerApp(packageName: String): Boolean = packageName in profileOwners
    }
}
