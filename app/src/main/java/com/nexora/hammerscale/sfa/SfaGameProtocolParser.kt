package com.nexora.hammerscale.sfa

import com.nexora.hammerscale.model.GameEvent
import com.nexora.hammerscale.model.LiveMessage
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.Inflater

/**
 * SFA copy of GameProtocolParser — independent so SF3 edits don't break SFA.
 * Handles SFA-NEBU-1 handshake + generic command dump (dev mode) + basic battle detection.
 * No SF3 raid/clan patch logic; pure observer for SFA.
 */
object SfaGameProtocolParser {

    // For SFA we still recognize same shape but keep generic
    private val SFA_BATTLE_COMMANDS = setOf(
        "brawler_start", "brawler_finish", "finish_fight",
        "start_fight", "get_battles",
        "event_battle_start_fight", "event_battle_finish_fight",
        "clan_start_fight", "clan_finish_fight",
        "get_player", "get_accounts", "get_brawler_pool", "get_leaderboard",
        "ping", "LOGIN", "HANDSHAKE", "join_zone", "process_offline_batch",
        "roguelike_enter_chapter", "quest_refresh_event", "promo_offers_update_event"
    )

    fun parse(data: ByteArray, direction: LiveMessage.Direction): GameEvent? {
        if (data.size < 3) return null
        val proto = extractPayload(data)
        if (proto != null) {
            val protoResult = try { parseEnvelope(proto, direction) } catch (_: Exception) { null }
            if (protoResult != null) return protoResult
        }
        val rawText = data.toString(Charsets.ISO_8859_1)
        return rawTextScan(rawText, direction)
    }

    private fun rawTextScan(text: String, dir: LiveMessage.Direction): GameEvent? {
        // Keep simple: if handshake string appears, surface it
        if (text.contains("HANDSHAKE")) {
            return if (dir == LiveMessage.Direction.OUTBOUND) GameEvent.HandshakeOut("SFA-NEBU-1")
            else GameEvent.HandshakeIn("?")
        }
        // Generic: try to extract any command name that looks like SFA command
        // Fall back to hex dump event via Command
        return null
    }

    fun extractCounter(data: ByteArray): Long? {
        val payload = extractPayload(data) ?: return null
        return (readProtoFields(payload)[1] as? Long)?.takeIf { it > 0 }
    }

    fun extractPingNetData(frame: ByteArray): ByteArray? {
        val payload = extractPayload(frame) ?: return null
        val outer = readProtoFields(payload)
        val cmd = (outer[2] as? ByteArray)?.toString(Charsets.UTF_8) ?: return null
        if (cmd != "ping") return null
        val params = outer[3] as? ByteArray ?: return null
        return readProtoFields(params)[2] as? ByteArray
    }

    fun extractPayload(data: ByteArray): ByteArray? {
        return when (data[0].toInt() and 0xFF) {
            0x01 -> {
                val len = data[1].toInt() and 0xFF
                if (data.size < 2 + len) null else data.copyOfRange(2, 2 + len)
            }
            0x02 -> {
                if (data.size < 5) null
                else {
                    val len = ByteBuffer.wrap(data, 1, 4).order(ByteOrder.LITTLE_ENDIAN).int
                    if (len <= 0 || data.size < 5 + len) null
                    else rawDeflate(data.copyOfRange(5, 5 + len))
                }
            }
            0x03 -> {
                if (data.size < 2) null
                else {
                    val len = data[1].toInt() and 0xFF
                    if (data.size < 2 + len) null
                    else rawDeflate(data.copyOfRange(2, 2 + len))
                }
            }
            else -> null
        }
    }

    private fun parseEnvelope(proto: ByteArray, dir: LiveMessage.Direction): GameEvent? {
        val fields  = readProtoFields(proto)
        val command = (fields[2] as? ByteArray)?.toString(Charsets.UTF_8) ?: return null
        val params  = fields[3] as? ByteArray
        val isOut   = dir == LiveMessage.Direction.OUTBOUND

        return when {
            command == "HANDSHAKE" && isOut -> {
                val name = params?.let { p ->
                    (readProtoFields(p)[1] as? ByteArray)?.toString(Charsets.UTF_8)
                } ?: "SFA-NEBU-1"
                GameEvent.HandshakeOut(name)
            }
            command == "HANDSHAKE" && !isOut -> {
                val token = params?.let { p ->
                    val top = (readProtoFields(p)[2] as? ByteArray)
                    top?.let { readProtoFields(it)[2] as? ByteArray }
                        ?.toString(Charsets.UTF_8)
                        ?: top?.toString(Charsets.UTF_8)
                } ?: "?"
                GameEvent.HandshakeIn(token)
            }
            command == "LOGIN" && isOut -> {
                val (guid, pass) = extractLoginCredentials(params)
                GameEvent.LoginOut(guid, pass)
            }
            command == "LOGIN" && !isOut -> GameEvent.LoginIn()
            // SFA dev mode: just like SF3 — show command name, first line handled by adapter (no params blob)
            else -> GameEvent.Command(command, isOut)
        }
    }

    private fun extractLoginCredentials(params: ByteArray?): Pair<String, String> {
        if (params == null) return "?" to "?"
        return try {
            val authWrapper = (readProtoFields(params)[2] as? ByteArray) ?: return scanRaw(params)
            val jsonBytes   = (readProtoFields(authWrapper)[2] as? ByteArray) ?: return scanRaw(params)
            val json = jsonBytes.toString(Charsets.UTF_8)
            val guid = extractJsonValue(json, "login")    ?: return scanRaw(params)
            val pass = extractJsonValue(json, "password") ?: return scanRaw(params)
            guid to pass
        } catch (_: Exception) {
            scanRaw(params)
        }
    }

    private fun scanRaw(data: ByteArray): Pair<String, String> {
        val text = data.toString(Charsets.ISO_8859_1)
        val guid = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .find(text)?.value ?: "?"
        val pass = Regex("[0-9a-f]{32}").find(text)?.value ?: "?"
        return guid to pass
    }

    fun readProtoFields(data: ByteArray): Map<Int, Any> {
        val result = LinkedHashMap<Int, Any>()
        var pos = 0
        while (pos < data.size) {
            val (tag, tagLen) = readVarint(data, pos) ?: break
            pos += tagLen
            val fieldNum  = (tag shr 3).toInt()
            val wireType  = (tag and 7L).toInt()
            when (wireType) {
                0 -> {
                    val (v, len) = readVarint(data, pos) ?: break
                    result[fieldNum] = v
                    pos += len
                }
                2 -> {
                    val (len, lenLen) = readVarint(data, pos) ?: break
                    pos += lenLen
                    val bytes = len.toInt()
                    if (pos + bytes > data.size) break
                    result[fieldNum] = data.copyOfRange(pos, pos + bytes)
                    pos += bytes
                }
                1 -> pos += 8
                5 -> pos += 4
                else -> break
            }
        }
        return result
    }

    private fun readVarint(data: ByteArray, start: Int): Pair<Long, Int>? {
        var value = 0L
        var shift = 0
        var i = start
        while (i < data.size) {
            val b = data[i++].toInt() and 0xFF
            value = value or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) return value to (i - start)
            shift += 7
            if (shift >= 64) break
        }
        return null
    }

    private fun rawDeflate(data: ByteArray): ByteArray? = try {
        val inflater = Inflater(true)
        inflater.setInput(data)
        val out = java.io.ByteArrayOutputStream(data.size * 3)
        val buf = ByteArray(8192)
        while (!inflater.finished()) {
            val n = inflater.inflate(buf)
            if (n > 0) out.write(buf, 0, n)
            else if (inflater.needsInput()) break
        }
        inflater.end()
        out.toByteArray().takeIf { it.isNotEmpty() }
    } catch (_: Exception) { null }

    private fun extractJsonValue(json: String, key: String): String? =
        Regex(""""$key"\s*:\s*"([^"]+)"""").find(json)?.groupValues?.get(1)
}
