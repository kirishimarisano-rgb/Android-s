package com.islandcompanion.suite.feature.netguard.engine

import com.islandcompanion.suite.core.rules.DomainBlocklistEngine
import com.islandcompanion.suite.core.rules.NetGuardConfig
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class LocalPolicySocks5ServerTest {

    @Test
    fun tcpConnect_forwardsCompleteTlsClientHelloWhenDomainAllowed() {
        val receivedLatch = CountDownLatch(1)
        var receivedBytes = ByteArray(0)
        val echoServer = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val echoThread = Thread {
            echoServer.accept().use { conn ->
                val buf = ByteArray(4096)
                val n = conn.getInputStream().read(buf)
                if (n > 0) {
                    receivedBytes = buf.copyOf(n)
                    conn.getOutputStream().write("SERVER_OK".toByteArray())
                    conn.getOutputStream().flush()
                }
                receivedLatch.countDown()
            }
        }.apply { start() }

        val blocklist = DomainBlocklistEngine(listOf("blocked.example.com"))
        val socksServer = LocalPolicySocks5Server(
            configProvider = { NetGuardConfig(blockLan = false) },
            blocklistEngine = blocklist,
            lookupAppForTarget = { _, _ -> AppIdentity(10001, "TestApp", "com.test.app") },
            protectSocket = { true },
            protectDatagramSocket = { true },
        )

        val socksPort = socksServer.start()
        try {
            val clientHello = buildMinimalClientHello("allowed.example.com")
            Socket("127.0.0.1", socksPort).use { client ->
                client.soTimeout = 3000
                val out = client.getOutputStream()
                val inp = client.getInputStream()

                // SOCKS5 greeting
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val greetingReply = ByteArray(2)
                inp.read(greetingReply)
                assertArrayEquals(byteArrayOf(0x05, 0x00), greetingReply)

                // SOCKS5 CONNECT 127.0.0.1:<echoServer.localPort>
                val port = echoServer.localPort
                out.write(
                    byteArrayOf(
                        0x05, 0x01, 0x00, 0x01,
                        127, 0, 0, 1,
                        ((port ushr 8) and 0xFF).toByte(),
                        (port and 0xFF).toByte(),
                    ),
                )
                out.flush()
                val connectReply = ByteArray(10)
                inp.read(connectReply)
                assertEquals(0x00, connectReply[1].toInt() and 0xFF)

                // Send TLS ClientHello and read server response
                out.write(clientHello)
                out.flush()

                val respBuf = ByteArray(64)
                val respLen = inp.read(respBuf)
                assertEquals("SERVER_OK", String(respBuf, 0, respLen))
            }

            assertTrue(receivedLatch.await(3, TimeUnit.SECONDS))
            assertArrayEquals(clientHello, receivedBytes)
        } finally {
            socksServer.stop()
            echoServer.close()
            echoThread.join(1000)
        }
    }

    @Test
    fun tcpConnect_blocksConnectionWhenTlsSniMatchesBlocklist() {
        val blocklist = DomainBlocklistEngine(listOf("tracker.example.com"))
        val socksServer = LocalPolicySocks5Server(
            configProvider = { NetGuardConfig(blockLan = false) },
            blocklistEngine = blocklist,
            lookupAppForTarget = { _, _ -> AppIdentity(10002, "TrackerApp", "com.tracker") },
            protectSocket = { true },
            protectDatagramSocket = { true },
        )

        val socksPort = socksServer.start()
        try {
            val clientHello = buildMinimalClientHello("sub.tracker.example.com")
            Socket("127.0.0.1", socksPort).use { client ->
                client.soTimeout = 3000
                val out = client.getOutputStream()
                val inp = client.getInputStream()

                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                inp.read(ByteArray(2))

                // Target any port; server must drop upon seeing blocked SNI before connecting upstream
                out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xBB.toByte()))
                out.flush()
                inp.read(ByteArray(10))

                out.write(clientHello)
                out.flush()

                // Connection should be closed immediately (EOF = -1)
                val nextByte = inp.read()
                assertEquals(-1, nextByte)
            }
        } finally {
            socksServer.stop()
        }
    }

    private fun buildMinimalClientHello(hostname: String): ByteArray {
        val hostBytes = hostname.toByteArray(Charsets.US_ASCII)
        val sniBody = ByteArrayOutputStream().apply {
            val listLen = 3 + hostBytes.size
            write((listLen ushr 8) and 0xFF)
            write(listLen and 0xFF)
            write(0x00)
            write((hostBytes.size ushr 8) and 0xFF)
            write(hostBytes.size and 0xFF)
            write(hostBytes)
        }.toByteArray()
        val extensions = ByteArrayOutputStream().apply {
            write(0x00)
            write(0x00)
            write((sniBody.size ushr 8) and 0xFF)
            write(sniBody.size and 0xFF)
            write(sniBody)
        }.toByteArray()
        val body = ByteArrayOutputStream().apply {
            write(0x03)
            write(0x03)
            write(ByteArray(32) { 0x22 })
            write(0x00)
            write(0x00)
            write(0x02)
            write(0x13)
            write(0x01)
            write(0x01)
            write(0x00)
            write((extensions.size ushr 8) and 0xFF)
            write(extensions.size and 0xFF)
            write(extensions)
        }.toByteArray()
        val handshake = ByteArrayOutputStream().apply {
            write(0x01)
            write((body.size ushr 16) and 0xFF)
            write((body.size ushr 8) and 0xFF)
            write(body.size and 0xFF)
            write(body)
        }.toByteArray()
        return ByteArrayOutputStream().apply {
            write(0x16)
            write(0x03)
            write(0x01)
            write((handshake.size ushr 8) and 0xFF)
            write(handshake.size and 0xFF)
            write(handshake)
        }.toByteArray()
    }
}
