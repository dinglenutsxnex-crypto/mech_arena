package com.nexora.hammerscale.sfa

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Patches SFA process_offline_batch (local_fight_finish) to win.
 * Based on comparison of instaleave (leave) vs win (all rounds) pcap:
 *  - deep[3] 3->1 (result)
 *  - deep[4] 1002->1001
 *  - deep[5] sub[1] 1->12 (instance? keep win value)
 *  - deep[5] sub[5] 1:4 -> 7:4 (won rounds = required rounds -> win)
 *  - deep[10] 3->4
 *  Generic: patch by walking proto fields and setting values.
 *  Also auto-detects round count: if not in SfaBattleConfig, uses required rounds from packet (field2).
 */
object SfaChroniclePatcher {

    fun isProcessOfflineBatch(data: ByteArray): Boolean {
        val p = SfaGameProtocolParser.extractPayload(data) ?: return false
        val f = SfaGameProtocolParser.readProtoFields(p)
        val cmd = (f[2] as? ByteArray)?.toString(Charsets.UTF_8) ?: return false
        return cmd == "process_offline_batch"
    }

    fun patchToWin(data: ByteArray, roundsOverride: Int? = null): ByteArray? {
        // Handle all framings 0x01 / 0x02 / 0x03 via extractPayload, then rebuild with same framing type
        try {
            val origType = data[0].toInt() and 0xFF
            if (origType != 0x01 && origType != 0x02 && origType != 0x03) return null
            val payload = SfaGameProtocolParser.extractPayload(data) ?: return null
            val outer = SfaGameProtocolParser.readProtoFields(payload)
            val counter = outer[1] as? Long ?: return null
            val paramsBlob = outer[3] as? ByteArray ?: return null
            // params is field1 containing 961 bytes
            val paramFields = SfaGameProtocolParser.readProtoFields(paramsBlob)
            // Actually params is single field1? In SFA, outer params is {1:961 ...}
            // The 961 blob is at field1 of params? Wait check: outer params = {1:961}
            // That 961 blob is inner with local_fight_finish
            val innerBlob = paramFields[1] as? ByteArray ?: return null
            val inner = SfaGameProtocolParser.readProtoFields(innerBlob).toMutableMap()
            // Only patch chronicle local_fight_finish, not confirm_video_ad etc
            val innerCmd = inner[2] as? ByteArray ?: return null
            if (innerCmd.toString(Charsets.UTF_8) != "local_fight_finish") return null
            var deepBlob = inner[4] as? ByteArray ?: return null
            // Patch deep
            val patchedDeep = patchDeep(deepBlob, roundsOverride)
                ?: return null
            // Rebuild inner
            inner[4] = patchedDeep
            // Also patch inner[1] from 1184 -> 1152? For win, 1184->1152 (instance version) - keep win value 1152
            // If inner[1] == 1184 (leave) set to 1152
            if ((inner[1] as? Long) == 1184L) inner[1] = 1152L

            val newInnerBlob = buildProto(inner)
            // Rebuild params
            val newParamsBlob = buildProto(mapOf(1 to newInnerBlob))
            val newPayload = buildEnvelopeWithType("process_offline_batch", newParamsBlob, counter, origType)
            return newPayload
        } catch (e: Exception) {
            android.util.Log.w("SfaChroniclePatcher", "patch failed ${e.message}")
            return null
        }
    }

    private fun patchDeep(deep: ByteArray, roundsOverride: Int?): ByteArray? {
        val fields = SfaGameProtocolParser.readProtoFields(deep).toMutableMap()
        // deep[3] 3->1 (win) - leave is 3, win is 1
        if ((fields[3] as? Long) == 3L) fields[3] = 1L
        // deep[4] 1002->1001 (also handle 1187 etc via inner check, but deep 1002 is leave)
        if ((fields[4] as? Long) == 1002L) fields[4] = 1001L
        // deep[10] 3->4 or 1->4 (both leave variants -> win 4)
        val d10 = fields[10] as? Long
        if (d10 == 3L || d10 == 1L) fields[10] = 4L

        // deep[5] is 857 bytes containing chronicle fight
        val deep5 = fields[5] as? ByteArray ?: return null
        val deep5Fields = SfaGameProtocolParser.readProtoFields(deep5).toMutableMap()

        // deep5[1] is 840 bytes sub fight
        val sub1 = deep5Fields[1] as? ByteArray
        if (sub1 != null) {
            val sub1Fields = SfaGameProtocolParser.readProtoFields(sub1).toMutableMap()
            // sub1[1] 1->12
            if ((sub1Fields[1] as? Long) == 1L) sub1Fields[1] = 12L
            deep5Fields[1] = buildProto(sub1Fields)
        }
        // deep5[3] 26:4 keep
        // deep5[5] is the rounds field: 01:04 -> 07:04 win (keep required 4, set won >=4)
        // User said 12/12 is required for chronicle, but actual win for 30126 is 7:4 (sub1 12:12 is the 12). Keep f5 required 4, won 12.
        val deep5Field5 = deep5Fields[5] as? ByteArray
        if (deep5Field5 != null) {
            val f5 = SfaGameProtocolParser.readProtoFields(deep5Field5).toMutableMap()
            val required = (f5[2] as? Long)?.toInt() ?: 4
            // For chronicle, won should be >= required, 12 is safe (matches sub1 12)
            val targetWon = roundsOverride ?: 12
            val won = if (targetWon < required) required else targetWon
            f5[1] = won.toLong()
            // Keep required as 4 (don't force to 12) - server expects 4 for this battle
            // f5[2] stays 4
            deep5Fields[5] = buildProto(f5)
        }
        fields[5] = buildProto(deep5Fields)
        return buildProto(fields)
    }

    private fun buildProto(fields: Map<Int, Any>): ByteArray {
        val out = mutableListOf<Byte>()
        // Sort by key to keep deterministic but original order was numeric ascending, preserve that
        for ((num, value) in fields.toSortedMap()) {
            when (value) {
                is Long -> {
                    writeVarint(out, (num.toLong() shl 3) or 0)
                    writeVarint(out, value)
                }
                is ByteArray -> {
                    writeVarint(out, (num.toLong() shl 3) or 2)
                    writeVarint(out, value.size.toLong())
                    value.forEach { out.add(it) }
                }
                is Int -> {
                    writeVarint(out, (num.toLong() shl 3) or 0)
                    writeVarint(out, value.toLong())
                }
            }
        }
        return out.toByteArray()
    }

    private fun buildEnvelope(cmd: String, params: ByteArray, counter: Long): ByteArray {
        val bodyFields = mutableMapOf<Int, Any>()
        bodyFields[1] = counter
        bodyFields[2] = cmd.toByteArray(Charsets.UTF_8)
        bodyFields[3] = params
        val body = buildProto(bodyFields)
        return if (body.size <= 255) {
            byteArrayOf(0x01, body.size.toByte()) + body
        } else {
            val compressed = rawDeflate(body)
            byteArrayOf(0x02) + ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(compressed.size).array() + compressed
        }
    }

    private fun buildEnvelopeWithType(cmd: String, params: ByteArray, counter: Long, origType: Int): ByteArray {
        val bodyFields = mutableMapOf<Int, Any>()
        bodyFields[1] = counter
        bodyFields[2] = cmd.toByteArray(Charsets.UTF_8)
        bodyFields[3] = params
        val body = buildProto(bodyFields)
        return when (origType) {
            0x01 -> if (body.size <= 255) byteArrayOf(0x01, body.size.toByte()) + body else {
                val c = rawDeflate(body)
                byteArrayOf(0x02) + ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(c.size).array() + c
            }
            0x03 -> {
                val c = rawDeflate(body)
                if (c.size <= 255) byteArrayOf(0x03, c.size.toByte()) + c
                else byteArrayOf(0x02) + ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(c.size).array() + c
            }
            else -> { // 0x02
                val c = rawDeflate(body)
                byteArrayOf(0x02) + ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(c.size).array() + c
            }
        }
    }

    private fun rawDeflate(data: ByteArray): ByteArray {
        val deflater = java.util.zip.Deflater(6, true)
        deflater.setInput(data)
        deflater.finish()
        val out = java.io.ByteArrayOutputStream(data.size)
        val buf = ByteArray(8192)
        while (!deflater.finished()) {
            val n = deflater.deflate(buf)
            if (n > 0) out.write(buf, 0, n)
        }
        deflater.end()
        return out.toByteArray()
    }

    private fun writeVarint(buf: MutableList<Byte>, value: Long) {
        var v = value
        while (v and -0x80L != 0L) {
            buf.add(((v and 0x7F) or 0x80L).toByte())
            v = v ushr 7
        }
        buf.add((v and 0x7F).toByte())
    }
}
