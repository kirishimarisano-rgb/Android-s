package com.islandcompanion.suite.feature.netguard.packet

/**
 * 純明文 TLS `ClientHello` SNI（Server Name Indication）擷取器。
 *
 * 僅讀取 TLS 交握首包中的明文 SNI 延伸欄位，絕不終止或解密 HTTPS 流量，完全不需安裝自簽 CA 憑證。
 */
object TlsSniExtractor {
    private const val TLS_CONTENT_TYPE_HANDSHAKE = 0x16
    private const val TLS_HANDSHAKE_CLIENT_HELLO = 0x01
    private const val TLS_EXT_SERVER_NAME = 0x0000
    private const val SNI_NAME_TYPE_HOST_NAME = 0x00

    /**
     * 從 TCP 首段位元組 [data]（長度 [length]）嘗試擷取 TLS SNI 主機名稱。
     * 若非 TLS ClientHello、格式不完整或未攜帶 SNI，則回傳 `null`。
     */
    fun extractSni(data: ByteArray, length: Int = data.size): String? {
        if (length < 43) return null

        // TLS Record Header: ContentType(1) + LegacyVersion(2) + Length(2)
        if ((data[0].toInt() and 0xFF) != TLS_CONTENT_TYPE_HANDSHAKE) return null
        val majorVersion = data[1].toInt() and 0xFF
        if (majorVersion != 0x03) return null

        val recordLength = readUInt16(data, 3)
        val recordEnd = (5 + recordLength).coerceAtMost(length)
        if (recordEnd < 43) return null

        // Handshake Header: HandshakeType(1) + Length(3)
        var pos = 5
        if ((data[pos].toInt() and 0xFF) != TLS_HANDSHAKE_CLIENT_HELLO) return null
        val handshakeLen = readUInt24(data, pos + 1)
        pos += 4
        val handshakeEnd = (pos + handshakeLen).coerceAtMost(recordEnd)

        // ClientVersion(2) + Random(32)
        pos += 2 + 32
        if (pos + 1 > handshakeEnd) return null

        // SessionID
        val sessionIdLen = data[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen
        if (pos + 2 > handshakeEnd) return null

        // CipherSuites
        val cipherSuitesLen = readUInt16(data, pos)
        pos += 2 + cipherSuitesLen
        if (pos + 1 > handshakeEnd) return null

        // CompressionMethods
        val compressionLen = data[pos].toInt() and 0xFF
        pos += 1 + compressionLen
        if (pos + 2 > handshakeEnd) return null

        // Extensions
        val extensionsLen = readUInt16(data, pos)
        pos += 2
        val extensionsEnd = (pos + extensionsLen).coerceAtMost(handshakeEnd)

        while (pos + 4 <= extensionsEnd) {
            val extType = readUInt16(data, pos)
            val extLen = readUInt16(data, pos + 2)
            pos += 4
            if (pos + extLen > extensionsEnd) return null

            if (extType == TLS_EXT_SERVER_NAME) {
                return parseSniExtension(data, pos, extLen)
            }
            pos += extLen
        }
        return null
    }

    private fun parseSniExtension(data: ByteArray, offset: Int, length: Int): String? {
        if (length < 5) return null
        val listLen = readUInt16(data, offset)
        var pos = offset + 2
        val end = (pos + listLen).coerceAtMost(offset + length)

        while (pos + 3 <= end) {
            val nameType = data[pos].toInt() and 0xFF
            val nameLen = readUInt16(data, pos + 1)
            pos += 3
            if (pos + nameLen > end) return null
            if (nameType == SNI_NAME_TYPE_HOST_NAME && nameLen > 0) {
                return String(data, pos, nameLen, Charsets.US_ASCII).lowercase()
            }
            pos += nameLen
        }
        return null
    }

    private fun readUInt16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    private fun readUInt24(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 16) or
            ((buf[offset + 1].toInt() and 0xFF) shl 8) or
            (buf[offset + 2].toInt() and 0xFF)
}
