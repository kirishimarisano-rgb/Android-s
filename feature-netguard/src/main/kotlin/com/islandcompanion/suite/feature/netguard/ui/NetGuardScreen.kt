package com.islandcompanion.suite.feature.netguard.ui

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.DeleteOutline
import androidx.compose.material.icons.outlined.FileUpload
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.Stop
import androidx.compose.material.icons.outlined.VpnLock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.islandcompanion.suite.core.rules.DnsUpstreamProtocol
import com.islandcompanion.suite.core.rules.NetGuardConfig
import com.islandcompanion.suite.core.rules.TrafficAction
import com.islandcompanion.suite.core.rules.TrafficLogEntry
import com.islandcompanion.suite.feature.netguard.engine.NetGuardDiagnostics
import com.islandcompanion.suite.feature.netguard.service.NetGuardVpnService
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 本機網路守門員（`:feature-netguard`）主畫面。
 * 提供 VPN 即時開關、引擎診斷卡片、即時流量日誌（可點擊網域一鍵封鎖）、防側漏設定與網域黑名單管理。
 */
@Composable
fun NetGuardScreen(
    viewModel: NetGuardViewModel,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            NetGuardVpnService.startService(context)
        }
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) {
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            NetGuardVpnService.startService(context)
        }
    }

    fun requestStartVpn() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            NetGuardVpnService.startService(context)
        }
    }

    Column(modifier = modifier.fillMaxSize()) {
        VpnStatusBanner(
            uiState = uiState,
            onToggleVpn = {
                if (uiState.isRunning) {
                    NetGuardVpnService.stopService(context)
                } else {
                    requestStartVpn()
                }
            },
            modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 6.dp),
        )

        EngineDiagnosticsCard(
            diagnostics = uiState.diagnostics,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        )

        uiState.feedbackMessage?.let { msg ->
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                shape = RoundedCornerShape(10.dp),
                color = MaterialTheme.colorScheme.secondaryContainer,
                contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = msg,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(onClick = viewModel::consumeFeedback) {
                        Text("關閉")
                    }
                }
            }
        }

        TabRow(selectedTabIndex = selectedTab) {
            Tab(
                selected = selectedTab == 0,
                onClick = { selectedTab = 0 },
                text = { Text("即時流量") },
            )
            Tab(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1 },
                text = { Text("防側漏設定") },
            )
            Tab(
                selected = selectedTab == 2,
                onClick = { selectedTab = 2 },
                text = { Text("黑名單 (${uiState.blockedDomains.size})") },
            )
        }

        when (selectedTab) {
            0 -> TrafficLogTab(
                logs = uiState.logs,
                onBlockDomain = viewModel::addBlockedDomain,
                onClearLogs = viewModel::clearLogs,
            )

            1 -> LeakGuardSettingsTab(
                config = uiState.config,
                onBlockLanChanged = viewModel::setBlockLan,
                onBlockStunChanged = viewModel::setBlockStun,
                onBlockQuicChanged = viewModel::setBlockQuic,
                onInterceptDnsChanged = viewModel::setInterceptDns,
                onSaveDnsUpstream = viewModel::updateDnsUpstream,
            )

            2 -> BlocklistTab(
                domains = uiState.blockedDomains,
                onAddDomain = viewModel::addBlockedDomain,
                onRemoveDomain = viewModel::removeBlockedDomain,
                onImportHosts = viewModel::importHostsText,
                onClearAll = viewModel::clearBlockedDomains,
            )
        }
    }
}

@Composable
private fun VpnStatusBanner(
    uiState: NetGuardUiState,
    onToggleVpn: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val containerColor = if (uiState.isRunning) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val contentColor = if (uiState.isRunning) {
        MaterialTheme.colorScheme.onPrimaryContainer
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = containerColor,
            contentColor = contentColor,
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.VpnLock,
                    contentDescription = null,
                    modifier = Modifier.size(28.dp),
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = if (uiState.isRunning) "守門員防護中" else "守門員已停止",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        text = uiState.statusMessage,
                        style = MaterialTheme.typography.labelMedium,
                        color = contentColor.copy(alpha = 0.85f),
                    )
                }
                Button(
                    onClick = onToggleVpn,
                    colors = if (uiState.isRunning) {
                        ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                            contentColor = MaterialTheme.colorScheme.onError,
                        )
                    } else {
                        ButtonDefaults.buttonColors()
                    },
                ) {
                    Icon(
                        imageVector = if (uiState.isRunning) Icons.Outlined.Stop else Icons.Outlined.PlayArrow,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(modifier = Modifier.size(4.dp))
                    Text(if (uiState.isRunning) "停止" else "啟動")
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = "已放行：${uiState.allowedCount}",
                    style = MaterialTheme.typography.labelMedium,
                )
                Text(
                    text = "已攔截：${uiState.blockedCount}",
                    style = MaterialTheme.typography.labelMedium,
                )
            }
        }
    }
}

@Composable
private fun EngineDiagnosticsCard(
    diagnostics: NetGuardDiagnostics,
    modifier: Modifier = Modifier,
) {
    val hasError = !diagnostics.lastError.isNullOrBlank()
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (hasError) {
                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.35f)
            } else {
                MaterialTheme.colorScheme.surface
            },
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = "引擎診斷",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
            )
            DiagnosticMetricRow(
                label = "TUN 讀取封包數",
                value = "${diagnostics.tunReadPackets}",
            )
            DiagnosticMetricRow(
                label = "送往 lwIP 封包數",
                value = "${diagnostics.sentToLwipPackets}",
            )
            DiagnosticMetricRow(
                label = "lwIP 回寫 TUN 封包數",
                value = "${diagnostics.lwipReturnPackets}（DoH 回寫 ${diagnostics.dnsResponsesWritten}）",
            )
            DiagnosticMetricRow(
                label = "lwIP 核心狀態",
                value = diagnostics.lwipStatus,
            )
            DiagnosticMetricRow(
                label = "SOCKS5 Relay 狀態",
                value = diagnostics.socks5Status,
            )
            DiagnosticMetricRow(
                label = "最後一筆錯誤訊息",
                value = diagnostics.lastError ?: "無",
                highlightError = hasError,
            )
        }
    }
}

@Composable
private fun DiagnosticMetricRow(
    label: String,
    value: String,
    highlightError: Boolean = false,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = "$label：",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.labelMedium,
            color = if (highlightError) {
                MaterialTheme.colorScheme.error
            } else {
                MaterialTheme.colorScheme.onSurface
            },
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun TrafficLogTab(
    logs: List<TrafficLogEntry>,
    onBlockDomain: (String) -> Unit,
    onClearLogs: () -> Unit,
) {
    var pendingBlockDomain by remember { mutableStateOf<String?>(null) }

    pendingBlockDomain?.let { domain ->
        AlertDialog(
            onDismissRequest = { pendingBlockDomain = null },
            title = { Text("加入網域黑名單") },
            text = { Text("確定要封鎖「$domain」及其所有子網域嗎？規則將立即生效並僅存於本機。") },
            confirmButton = {
                Button(
                    onClick = {
                        onBlockDomain(domain)
                        pendingBlockDomain = null
                    },
                ) {
                    Text("一鍵封鎖")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingBlockDomain = null }) {
                    Text("取消")
                }
            },
        )
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = "點擊含網域的紀錄可一鍵加入封鎖",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            TextButton(onClick = onClearLogs) {
                Text("清空日誌")
            }
        }

        if (logs.isEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(32.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = "尚無流量紀錄",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "啟動本機網路守門員後，所有 DNS / TLS SNI / IP 連線與攔截紀錄將即時顯示於此。",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(logs, key = { it.id }) { entry ->
                    TrafficLogCard(
                        entry = entry,
                        onClickDomain = { domain -> pendingBlockDomain = domain },
                    )
                }
            }
        }
    }
}

@Composable
private fun TrafficLogCard(
    entry: TrafficLogEntry,
    onClickDomain: (String) -> Unit,
) {
    val isBlocked = entry.action == TrafficAction.BLOCKED
    val timeText = remember(entry.timestampMs) {
        SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(entry.timestampMs))
    }

    Card(
        onClick = { entry.domain?.let(onClickDomain) },
        enabled = entry.domain != null,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isBlocked) {
                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.45f)
            } else {
                MaterialTheme.colorScheme.surfaceVariant
            },
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = if (isBlocked) Icons.Outlined.Block else Icons.Outlined.CheckCircle,
                    contentDescription = null,
                    tint = if (isBlocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary,
                    modifier = Modifier.size(18.dp),
                )
                Text(
                    text = entry.appName,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    text = "$timeText • ${entry.protocol}",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Text(
                text = entry.domain ?: "${entry.destinationIp}:${entry.destinationPort}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = "目標 IP：${entry.destinationIp}:${entry.destinationPort}",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = if (isBlocked) {
                        "已攔截 • ${entry.reason?.displayLabel ?: "規則"}"
                    } else {
                        "放行"
                    },
                    style = MaterialTheme.typography.labelMedium,
                    color = if (isBlocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary,
                )
            }
        }
    }
}

@Composable
private fun LeakGuardSettingsTab(
    config: NetGuardConfig,
    onBlockLanChanged: (Boolean) -> Unit,
    onBlockStunChanged: (Boolean) -> Unit,
    onBlockQuicChanged: (Boolean) -> Unit,
    onInterceptDnsChanged: (Boolean) -> Unit,
    onSaveDnsUpstream: (DnsUpstreamProtocol, String) -> Unit,
) {
    var selectedProtocol by remember(config.dnsProtocol) { mutableStateOf(config.dnsProtocol) }
    var upstreamInput by remember(config.dnsUpstream) { mutableStateOf(config.dnsUpstream) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            ToggleSettingCard(
                title = "區網隔離",
                subtitle = "丟棄發往私有網段（10/8、172.16/12、192.168/16、fc00::/7）與 mDNS（UDP 5353）/ SSDP（UDP 1900）的封包。",
                checked = config.blockLan,
                onCheckedChange = onBlockLanChanged,
            )
        }
        item {
            ToggleSettingCard(
                title = "防 WebRTC 探測（STUN / TURN）",
                subtitle = "封鎖常見 STUN/TURN 埠號（UDP 3478、5349），避免真實位址側漏。",
                checked = config.blockStun,
                onCheckedChange = onBlockStunChanged,
            )
        }
        item {
            ToggleSettingCard(
                title = "封鎖 UDP 443（強制 QUIC 降級為 TCP 443）",
                subtitle = "防止 App 透過 QUIC/HTTP3 繞過 TLS SNI 網域過濾，強制回退至標準 TCP 443。",
                checked = config.blockQuic,
                onCheckedChange = onBlockQuicChanged,
            )
        }
        item {
            ToggleSettingCard(
                title = "防 DNS 洩漏（攔截 UDP 53 轉加密上游）",
                subtitle = "攔截明文 UDP 53 查詢，套用本機黑名單並轉發至 DoH / DoT 加密伺服器。",
                checked = config.interceptDns,
                onCheckedChange = onInterceptDnsChanged,
            )
        }
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant,
                ),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text(
                        text = "加密 DNS 上游伺服器",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(
                            selected = selectedProtocol == DnsUpstreamProtocol.DOH,
                            onClick = {
                                selectedProtocol = DnsUpstreamProtocol.DOH
                                if (!upstreamInput.startsWith("https://")) {
                                    upstreamInput = NetGuardConfig.DEFAULT_DOH_UPSTREAM
                                }
                            },
                            label = { Text("DoH (HTTPS)") },
                        )
                        FilterChip(
                            selected = selectedProtocol == DnsUpstreamProtocol.DOT,
                            onClick = {
                                selectedProtocol = DnsUpstreamProtocol.DOT
                                if (upstreamInput.startsWith("https://")) {
                                    upstreamInput = NetGuardConfig.DEFAULT_DOT_UPSTREAM
                                }
                            },
                            label = { Text("DoT (TLS 853)") },
                        )
                    }
                    OutlinedTextField(
                        value = upstreamInput,
                        onValueChange = { upstreamInput = it },
                        label = {
                            Text(
                                if (selectedProtocol == DnsUpstreamProtocol.DOH) {
                                    "DoH URL（例如 https://dns.quad9.net/dns-query）"
                                } else {
                                    "DoT 主機（例如 dns.quad9.net）"
                                },
                            )
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(
                        onClick = { onSaveDnsUpstream(selectedProtocol, upstreamInput) },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("套用 DNS 上游設定")
                    }
                }
            }
        }
    }
}

@Composable
private fun ToggleSettingCard(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = title, style = MaterialTheme.typography.titleMedium)
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(checked = checked, onCheckedChange = onCheckedChange)
        }
    }
}

@Composable
private fun BlocklistTab(
    domains: List<String>,
    onAddDomain: (String) -> Unit,
    onRemoveDomain: (String) -> Unit,
    onImportHosts: (String, Boolean) -> Unit,
    onClearAll: () -> Unit,
) {
    val context = LocalContext.current
    var newDomainInput by rememberSaveable { mutableStateOf("") }
    var showImportDialog by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }

    val documentPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            val content = runCatching {
                context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
            }.getOrNull()
            if (!content.isNullOrBlank()) {
                onImportHosts(content, false)
            }
        }
    }

    if (showImportDialog) {
        AlertDialog(
            onDismissRequest = { showImportDialog = false },
            title = { Text("貼上 Hosts / 網域清單") },
            text = {
                OutlinedTextField(
                    value = importText,
                    onValueChange = { importText = it },
                    placeholder = { Text("0.0.0.0 ads.example.com\ntracker.example.net") },
                    minLines = 5,
                    maxLines = 10,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        onImportHosts(importText, false)
                        importText = ""
                        showImportDialog = false
                    },
                ) {
                    Text("匯入")
                }
            },
            dismissButton = {
                TextButton(onClick = { showImportDialog = false }) {
                    Text("取消")
                }
            },
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = newDomainInput,
                onValueChange = { newDomainInput = it },
                label = { Text("手動新增封鎖網域") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            Button(
                onClick = {
                    if (newDomainInput.isNotBlank()) {
                        onAddDomain(newDomainInput)
                        newDomainInput = ""
                    }
                },
            ) {
                Text("新增")
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedButton(
                onClick = { documentPicker.launch(arrayOf("text/*", "*/*")) },
                modifier = Modifier.weight(1f),
            ) {
                Icon(Icons.Outlined.FileUpload, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.size(4.dp))
                Text("匯入 Hosts 檔")
            }
            OutlinedButton(
                onClick = { showImportDialog = true },
                modifier = Modifier.weight(1f),
            ) {
                Text("貼上清單")
            }
            if (domains.isNotEmpty()) {
                TextButton(onClick = onClearAll) {
                    Text("清空")
                }
            }
        }

        HorizontalDivider()

        if (domains.isEmpty()) {
            Text(
                text = "目前尚無封鎖網域。可手動新增、匯入標準 Hosts 清單，或於「即時流量」分頁點擊網域一鍵加入。",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                items(domains, key = { it }) { domain ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant,
                        ),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = domain,
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.weight(1f),
                            )
                            IconButton(onClick = { onRemoveDomain(domain) }) {
                                Icon(
                                    imageVector = Icons.Outlined.DeleteOutline,
                                    contentDescription = "移除 $domain",
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
