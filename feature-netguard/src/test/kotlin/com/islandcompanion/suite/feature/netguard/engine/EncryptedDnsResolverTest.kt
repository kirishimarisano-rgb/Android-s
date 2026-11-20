package com.islandcompanion.suite.feature.netguard.engine

import com.islandcompanion.suite.core.rules.DnsUpstreamProtocol
import com.islandcompanion.suite.core.rules.NetGuardConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicReference

class EncryptedDnsResolverTest {

    @Test
    fun testConnectivity_sendsStandardRfc8484PostAndParsesIpv4Answer() {
        val capturedRequestLine = AtomicReference("")
        val capturedHeaders = AtomicReference<Map<String, String>>(emptyMap())

        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val serverThread = Thread {
            server.accept().use { client ->
                val input = BufferedInputStream(client.getInputStream())
                val headerBytes = readUntilHeadersEnd(input)
                val headerLines = String(headerBytes, Charsets.US_ASCII).split("\r\n")
                capturedRequestLine.set(headerLines.firstOrNull().orEmpty())

                val headers = headerLines.drop(1)
                    .filter { it.contains(':') }
                    .associate { line ->
                        line.substringBefore(':').trim().lowercase() to line.substringAfter(':').trim()
                    }
                capturedHeaders.set(headers)

                val contentLength = headers["content-length"]?.toIntOrNull() ?: 0
                val body = ByteArray(contentLength)
                var read = 0
                while (read < contentLength) {
                    val n = input.read(body, read, contentLength - read)
                    if (n <= 0) break
                    read += n
                }

                // Synthesize valid A record answer (93.184.215.14)
                val dnsResp = body.copyOf(body.size + 16)
                dnsResp[2] = 0x81.toByte()
                dnsResp[3] = 0x80.toByte()
                dnsResp[7] = 0x01
                val p = body.size
                dnsResp[p] = 0xC0.toByte()
                dnsResp[p + 1] = 0x0C
                dnsResp[p + 3] = 0x01
                dnsResp[p + 5] = 0x01
                dnsResp[p + 11] = 0x04
                dnsResp[p + 12] = 93
                dnsResp[p + 13] = 184.toByte()
                dnsResp[p + 14] = 215.toByte()
                dnsResp[p + 15] = 14

                val httpResp = buildString {
                    append("HTTP/1.1 200 OK\r\n")
                    append("Content-Type: application/dns-message\r\n")
                    append("Content-Length: ${dnsResp.size}\r\n")
                    append("Connection: close\r\n\r\n")
                }.toByteArray(Charsets.US_ASCII)

                client.getOutputStream().apply {
                    write(httpResp)
                    write(dnsResp)
                    flush()
                }
            }
        }.apply { start() }

        try {
            val resolver = EncryptedDnsResolver(protectSocket = { true })
            val result = resolver.testConnectivity(
                NetGuardConfig(
                    dnsProtocol = DnsUpstreamProtocol.DOH,
                    dnsUpstream = "http://127.0.0.1:${server.localPort}/dns-query",
                ),
            )

            assertTrue(result.success)
            assertEquals(listOf("93.184.215.14"), result.resolvedIps)
            assertTrue(capturedRequestLine.get().startsWith("POST /dns-query HTTP/1.1"))
            assertEquals("application/dns-message", capturedHeaders.get()["content-type"])
            assertEquals("application/dns-message", capturedHeaders.get()["accept"])
        } finally {
            server.close()
            serverThread.join(2000)
        }
    }

    @Test
    fun testConnectivity_reportsHttpErrorStatusExplicitly() {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val serverThread = Thread {
            server.accept().use { client ->
                readUntilHeadersEnd(BufferedInputStream(client.getInputStream()))
                val httpResp = "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                client.getOutputStream().write(httpResp.toByteArray(Charsets.US_ASCII))
                client.getOutputStream().flush()
            }
        }.apply { start() }

        try {
            val resolver = EncryptedDnsResolver(protectSocket = { true })
            val result = resolver.testConnectivity(
                NetGuardConfig(
                    dnsProtocol = DnsUpstreamProtocol.DOH,
                    dnsUpstream = "http://127.0.0.1:${server.localPort}/dns-query",
                ),
            )

            assertFalse(result.success)
            assertTrue(result.errorMessage.orEmpty().contains("HTTP 505"))
        } finally {
            server.close()
            serverThread.join(2000)
        }
    }

    private fun readUntilHeadersEnd(input: BufferedInputStream): ByteArray {
        val out = ArrayList<Byte>()
        while (true) {
            val b = input.read()
            if (b < 0) break
            out.add(b.toByte())
            val size = out.size
            if (size >= 4 &&
                out[size - 4] == '\r'.code.toByte() &&
                out[size - 3] == '\n'.code.toByte() &&
                out[size - 2] == '\r'.code.toByte() &&
                out[size - 1] == '\n'.code.toByte()
            ) {
                break
            }
        }
        return out.toByteArray()
    }
}
