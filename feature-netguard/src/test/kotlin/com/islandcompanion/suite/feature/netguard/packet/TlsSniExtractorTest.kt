package com.islandcompanion.suite.feature.netguard.packet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayOutputStream

class TlsSniExtractorTest {

    @Test
    fun extractSni_extractsHostnameFromValidTlsClientHello() {
        val clientHello = buildTlsClientHello("api.Tracker.Example.com")

        val sni = TlsSniExtractor.extractSni(clientHello)

        assertEquals("api.tracker.example.com", sni)
    }

    @Test
    fun extractSni_returnsNullForPlainHttpOrNonTlsTraffic() {
        val httpGet = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray(Charsets.US_ASCII)

        assertNull(TlsSniExtractor.extractSni(httpGet))
    }

    @Test
    fun extractSni_returnsNullForTruncatedTlsRecord() {
        val truncated = buildTlsClientHello("example.com").copyOf(30)

        assertNull(TlsSniExtractor.extractSni(truncated))
    }

    private fun buildTlsClientHello(hostname: String): ByteArray {
        val hostBytes = hostname.toByteArray(Charsets.US_ASCII)

        // SNI extension body: listLen(2) + type(1=0x00) + nameLen(2) + hostBytes
        val sniBody = ByteArrayOutputStream().apply {
            val listLen = 3 + hostBytes.size
            write((listLen ushr 8) and 0xFF)
            write(listLen and 0xFF)
            write(0x00)
            write((hostBytes.size ushr 8) and 0xFF)
            write(hostBytes.size and 0xFF)
            write(hostBytes)
        }.toByteArray()

        // Extensions: extType(0x0000) + extLen(2) + sniBody
        val extensions = ByteArrayOutputStream().apply {
            write(0x00)
            write(0x00)
            write((sniBody.size ushr 8) and 0xFF)
            write(sniBody.size and 0xFF)
            write(sniBody)
        }.toByteArray()

        // Handshake body: TLS 1.2(0x0303) + Random(32) + SessionIdLen(0) + CipherSuites(2 bytes: 0x1301)
        // + Compression(1 byte: 0x00) + ExtensionsLen(2) + extensions
        val body = ByteArrayOutputStream().apply {
            write(0x03)
            write(0x03)
            write(ByteArray(32) { 0x11 })
            write(0x00) // Session ID len
            write(0x00)
            write(0x02) // Cipher suites len
            write(0x13)
            write(0x01) // TLS_AES_128_GCM_SHA256
            write(0x01) // Compression methods len
            write(0x00) // null compression
            write((extensions.size ushr 8) and 0xFF)
            write(extensions.size and 0xFF)
            write(extensions)
        }.toByteArray()

        // Handshake header: ClientHello(0x01) + 3-byte length + body
        val handshake = ByteArrayOutputStream().apply {
            write(0x01)
            write((body.size ushr 16) and 0xFF)
            write((body.size ushr 8) and 0xFF)
            write(body.size and 0xFF)
            write(body)
        }.toByteArray()

        // TLS Record header: Handshake(0x16) + TLS 1.0(0x0301) + 2-byte length + handshake
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
