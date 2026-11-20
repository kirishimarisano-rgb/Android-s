package com.islandcompanion.suite.core.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val DarkColors = darkColorScheme(
    primary = Color(0xFF4FD8EB),
    onPrimary = Color(0xFF00363D),
    primaryContainer = Color(0xFF004F58),
    onPrimaryContainer = Color(0xFF97F0FF),
    secondary = Color(0xFF81C784),
    onSecondary = Color(0xFF0B3912),
    secondaryContainer = Color(0xFF1F5126),
    onSecondaryContainer = Color(0xFFC8E6C9),
    tertiary = Color(0xFFFFB74D),
    onTertiary = Color(0xFF452B00),
    tertiaryContainer = Color(0xFF633F00),
    onTertiaryContainer = Color(0xFFFFDDB3),
    background = Color(0xFF0E1416),
    onBackground = Color(0xFFE0E3E4),
    surface = Color(0xFF131A1D),
    onSurface = Color(0xFFE0E3E4),
    surfaceVariant = Color(0xFF1E282C),
    onSurfaceVariant = Color(0xFFBFC8CC),
    outline = Color(0xFF3E4B50),
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF006874),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF97F0FF),
    onPrimaryContainer = Color(0xFF001F24),
    secondary = Color(0xFF2E6B35),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFB7F3B8),
    onSecondaryContainer = Color(0xFF002107),
    tertiary = Color(0xFF855400),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFFFDDB3),
    onTertiaryContainer = Color(0xFF2A1800),
    background = Color(0xFFF5F8F9),
    onBackground = Color(0xFF171D1E),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF171D1E),
    surfaceVariant = Color(0xFFE4ECEE),
    onSurfaceVariant = Color(0xFF3F484A),
    outline = Color(0xFF6F797A),
)

private val SuiteTypography = Typography(
    titleLarge = TextStyle(
        fontSize = 20.sp,
        lineHeight = 26.sp,
        fontWeight = FontWeight.SemiBold,
    ),
    titleMedium = TextStyle(
        fontSize = 16.sp,
        lineHeight = 22.sp,
        fontWeight = FontWeight.SemiBold,
    ),
    bodyMedium = TextStyle(
        fontSize = 14.sp,
        lineHeight = 20.sp,
        fontWeight = FontWeight.Normal,
    ),
    labelMedium = TextStyle(
        fontSize = 12.sp,
        lineHeight = 16.sp,
        fontWeight = FontWeight.Medium,
    ),
)

/**
 * Island Companion Security Suite 共用 Material 3 主題，優先針對深色模式與高對比安全工具風格最佳化。
 */
@Composable
fun IslandCompanionTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColors else LightColors
    MaterialTheme(
        colorScheme = colorScheme,
        typography = SuiteTypography,
        content = content,
    )
}
