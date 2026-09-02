package com.nexora.hammerscale.sfa

import android.net.VpnService
import com.nexora.hammerscale.model.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel as KChannel
import java.io.ByteArrayOutputStream
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap

/**
 * SFA copy of TcpHandler — independent so SF3 edits don't break SFA.
 * Strips SF3 raid/clan/brawler intercept logic; pure observer + injector for SFA-NEBU.
 */
data class SfaTcpConnState(
    val connId: String,
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    var localSeq: Long,
    var remoteSeq: Long,
    var channel: SocketChannel? = null,
    var status: SfaTcpStatus = SfaTcpStatus.SYN_RECEIVED,
    val outboundQueue: KChannel<ByteArray> = KChannel(KChannel.UNLIMITED),
    val writeLock: java.util.concurrent.locks.ReentrantLock = java.util.concurrent.locks.ReentrantLock(),
    var awaitingWsHandshake: Boolean = false,
    var isWebSocket: Boolean = false,
    val inboundWsBuffer: ByteArrayOutputStream = ByteArrayOutputStream(),
    val outboundWsBuffer: ByteArrayOutputStream = ByteArrayOutputStream(),
    val inboundSfaBuffer: ByteArrayOutputStream = ByteArrayOutputStream(),
    val outboundSfaBuffer: ByteArrayOutputStream = ByteArrayOutputStream(),
    var inboundResyncBytes: Int = 0
) {
    val key get() = "${srcIp.joinToString(".")}:$srcPort->${dstIp.joinToString(".")}:$dstPort"
}

enum class SfaTcpStatus { SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSED }

class SfaTcpHandler(
    private val vpnService: VpnService,
    private val vpnFd: FileDescriptor,
    private val onConnectionEvent: (ConnectionEntry) -> Unit,
    private val onMessage: (String, LiveMessage) -> Unit,
    private val onStatusChange: (String, ConnectionStatus) -> Unit,
    private val onWebSocket: (String) -> Unit = {}
) {
    private val connections = ConcurrentHashMap<String, SfaTcpConnState>()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val outStream = FileOutputStream(vpnFd)

    private fun extractCommandName(frame: ByteArray): String? {
        return try {
            val proto = SfaGameProtocolParser.extractPayload(frame) ?: return null
            val fields = SfaGameProtocolParser.readProtoFields(proto)
            val cmdBytes = fields[2] as? ByteArray ?: return null
            val cmd = cmdBytes.toString(Charsets.UTF_8)
            if (cmd.isNotBlank()) cmd else null
        } catch (_: Exception) { null }
    }

    private fun makeMessage(dir: LiveMessage.Direction, data: ByteArray, cmdName: String?): LiveMessage {
        return LiveMessage(dir, data, commandName = cmdName)
    }

    fun handlePacket(packet: com.nexora.hammerscale.net.ParsedPacket) {
        val tcp = packet.tcp ?: return
        val connKey = "${packet.ip.srcAddr.address.joinToString(".")}:${tcp.srcPort}->" +
                      "${packet.ip.dstAddr.address.joinToString(".")}:${tcp.dstPort}"
        when {
            tcp.isSYN && !tcp.isACK -> handleSyn(packet, tcp, connKey)
            tcp.isACK && !tcp.isSYN -> handleAck(packet, tcp, connKey)
            tcp.isFIN               -> handleFin(connKey)
            tcp.isRST               -> handleRst(connKey)
        }
    }

    private fun handleSyn(packet: com.nexora.hammerscale.net.ParsedPacket, tcp: com.nexora.hammerscale.net.TCPHeader, connKey: String) {
        val srcIp = packet.ip.srcAddr.address
        val dstIp = packet.ip.dstAddr.address
        val entry = ConnectionEntry(
            id = connKey,
            protocol = Protocol.TCP,
            srcPort = tcp.srcPort,
            dstIp = packet.ip.dstAddr.hostAddress ?: "?",
            dstPort = tcp.dstPort,
            status = ConnectionStatus.CONNECTING
        )
        onConnectionEvent(entry)
        val conn = SfaTcpConnState(
            connId = connKey,
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = tcp.srcPort,
            dstPort = tcp.dstPort,
            localSeq = (Math.random() * 0xFFFFFFFFL).toLong(),
            remoteSeq = (tcp.seqNum + 1L) and 0xFFFFFFFFL
        )
        connections[connKey] = conn
        sendSynAck(conn, tcp.seqNum)
        scope.launch {
            try {
                val channel = SocketChannel.open()
                channel.configureBlocking(false)
                vpnService.protect(channel.socket())
                channel.connect(InetSocketAddress(packet.ip.dstAddr, tcp.dstPort))
                var attempts = 0
                while (!channel.finishConnect() && attempts++ < 100) delay(10)
                if (!channel.isConnected) { channel.close(); cleanup(connKey); return@launch }
                channel.configureBlocking(true)
                conn.channel = channel
                conn.status = SfaTcpStatus.ESTABLISHED
                onStatusChange(connKey, ConnectionStatus.ACTIVE)
                launch { writerLoop(conn) }
                launch { readerLoop(conn) }
            } catch (e: Exception) { cleanup(connKey) }
        }
    }

    private fun handleAck(packet: com.nexora.hammerscale.net.ParsedPacket, tcp: com.nexora.hammerscale.net.TCPHeader, connKey: String) {
        val conn = connections[connKey] ?: return
        if (packet.payload.isEmpty()) return
        conn.remoteSeq = (tcp.seqNum + packet.payload.size.toLong()) and 0xFFFFFFFFL
        sendAck(conn)
        if (!conn.isWebSocket) {
            val text = String(packet.payload, Charsets.ISO_8859_1)
            if (text.contains("Upgrade: websocket", ignoreCase = true)) conn.awaitingWsHandshake = true
            // SFA: pure observer — no patching
            conn.outboundSfaBuffer.write(packet.payload)
            parseSfaFrames(conn.connId, conn.outboundSfaBuffer, LiveMessage.Direction.OUTBOUND)
            conn.outboundQueue.trySend(packet.payload)
        } else {
            conn.outboundWsBuffer.write(packet.payload)
            parseWsFrames(conn.connId, conn.outboundWsBuffer, LiveMessage.Direction.OUTBOUND)
            conn.outboundQueue.trySend(packet.payload)
        }
    }

    private fun handleFin(connKey: String) {
        val conn = connections[connKey] ?: return
        conn.status = SfaTcpStatus.FIN_WAIT
        onStatusChange(conn.connId, ConnectionStatus.CLOSING)
        conn.outboundQueue.close()
        scope.launch { conn.channel?.close(); cleanup(connKey) }
    }

    private fun handleRst(connKey: String) {
        val conn = connections.remove(connKey) ?: return
        conn.status = SfaTcpStatus.CLOSED
        conn.outboundQueue.close()
        onStatusChange(conn.connId, ConnectionStatus.CLOSED)
        scope.launch { try { conn.channel?.close() } catch (_: Exception) {} }
    }

    private suspend fun writerLoop(conn: SfaTcpConnState) {
        val ch = conn.channel ?: return
        try {
            for (data in conn.outboundQueue) {
                val buf = ByteBuffer.wrap(data)
                conn.writeLock.lock()
                try { while (buf.hasRemaining()) ch.write(buf) } finally { conn.writeLock.unlock() }
            }
        } catch (_: Exception) { cleanup(conn.key) }
    }

    private suspend fun readerLoop(conn: SfaTcpConnState) {
        val ch = conn.channel ?: return
        val buf = ByteBuffer.allocate(32768)
        try {
            while (conn.status == SfaTcpStatus.ESTABLISHED) {
                buf.clear()
                val read = withContext(Dispatchers.IO) { ch.read(buf) }
                if (read == -1) { sendFin(conn); cleanup(conn.key); break }
                if (read <= 0) continue
                buf.flip()
                val data = ByteArray(read).also { buf.get(it) }
                sendDataToApp(conn, data)
                if (!conn.isWebSocket && conn.awaitingWsHandshake) {
                    val text = String(data, Charsets.ISO_8859_1)
                    if (text.contains("101 Switching Protocols", ignoreCase = true)) {
                        conn.isWebSocket = true
                        conn.awaitingWsHandshake = false
                        onWebSocket(conn.connId)
                        onMessage(conn.connId, LiveMessage(LiveMessage.Direction.INBOUND, data))
                        continue
                    }
                }
                if (conn.isWebSocket) {
                    conn.inboundWsBuffer.write(data)
                    parseWsFrames(conn.connId, conn.inboundWsBuffer, LiveMessage.Direction.INBOUND)
                } else {
                    conn.inboundSfaBuffer.write(data)
                    parseSfaFrames(conn.connId, conn.inboundSfaBuffer, LiveMessage.Direction.INBOUND, conn)
                }
            }
        } catch (_: Exception) { cleanup(conn.key) }
    }

    private fun parseWsFrames(connId: String, buffer: ByteArrayOutputStream, dir: LiveMessage.Direction) {
        val raw = buffer.toByteArray(); buffer.reset()
        var offset = 0
        while (offset < raw.size) {
            if (offset + 2 > raw.size) break
            val b0 = raw[offset].toInt() and 0xFF
            val b1 = raw[offset + 1].toInt() and 0xFF
            val opcode = b0 and 0x0F
            val masked = (b1 and 0x80) != 0
            var payloadLen = (b1 and 0x7F).toLong()
            var headerSize = 2
            when {
                payloadLen == 126L -> { if (offset + 4 > raw.size) break; payloadLen = ((raw[offset+2].toInt() and 0xFF) shl 8 or (raw[offset+3].toInt() and 0xFF)).toLong(); headerSize=4 }
                payloadLen == 127L -> { if (offset + 10 > raw.size) break; payloadLen=0L; for (i in 0..7) payloadLen=(payloadLen shl 8) or (raw[offset+2+i].toInt() and 0xFF).toLong(); headerSize=10 }
            }
            val maskOffset = offset + headerSize
            val dataOffset = maskOffset + if (masked) 4 else 0
            val totalFrame = (dataOffset - offset) + payloadLen.toInt()
            if (offset + totalFrame > raw.size) break
            val payload = ByteArray(payloadLen.toInt())
            if (masked) {
                val key = raw.slice(maskOffset until maskOffset+4)
                for (i in payload.indices) payload[i] = (raw[dataOffset+i].toInt() xor (key[i%4].toInt() and 0xFF)).toByte()
            } else System.arraycopy(raw, dataOffset, payload, 0, payload.size)
            if (opcode in 0..2 && payload.isNotEmpty()) {
                val cmdName = extractCommandName(payload)
                onMessage(connId, makeMessage(dir, payload, cmdName))
            }
            offset += totalFrame
        }
        if (offset < raw.size) buffer.write(raw, offset, raw.size - offset)
    }

    companion object {
        private const val MAX_RESYNC_BYTES = 64
        private const val MAX_FRAME_BYTES = 8 * 1024 * 1024
    }

    private fun parseSfaFrames(connId: String, buffer: ByteArrayOutputStream, dir: LiveMessage.Direction, conn: SfaTcpConnState? = null) {
        val raw = buffer.toByteArray(); buffer.reset()
        var pos = 0
        while (pos < raw.size) {
            val t = raw[pos].toInt() and 0xFF
            when (t) {
                0x01 -> {
                    if (pos + 2 > raw.size) break
                    val len = raw[pos+1].toInt() and 0xFF
                    if (pos + 2 + len > raw.size) break
                    conn?.inboundResyncBytes = 0
                    val frame01 = raw.copyOfRange(pos, pos+2+len)
                    val cmdName = extractCommandName(frame01)
                    onMessage(connId, makeMessage(dir, frame01, cmdName))
                    pos += 2 + len
                }
                0x02 -> {
                    if (pos + 5 > raw.size) break
                    val compLen = ByteBuffer.wrap(raw, pos+1, 4).order(java.nio.ByteOrder.LITTLE_ENDIAN).int and 0x7FFFFFFF
                    when {
                        compLen <= 0 || compLen > MAX_FRAME_BYTES -> { if (conn!=null){conn.inboundResyncBytes++; if(conn.inboundResyncBytes>MAX_RESYNC_BYTES){conn.inboundResyncBytes=0; return}}; pos++ }
                        pos + 5 + compLen > raw.size -> break
                        else -> { conn?.inboundResyncBytes=0; val f=raw.copyOfRange(pos,pos+5+compLen); val cmdName=extractCommandName(f); onMessage(connId, makeMessage(dir,f,cmdName)); pos+=5+compLen }
                    }
                }
                0x03 -> {
                    if (pos + 2 > raw.size) break
                    val compLen = raw[pos+1].toInt() and 0xFF
                    when {
                        compLen <=0 -> { if(conn!=null){conn.inboundResyncBytes++; if(conn.inboundResyncBytes>MAX_RESYNC_BYTES){conn.inboundResyncBytes=0; return}}; pos++ }
                        pos + 2 + compLen > raw.size -> break
                        else -> { conn?.inboundResyncBytes=0; val f=raw.copyOfRange(pos,pos+2+compLen); val cmdName=extractCommandName(f); onMessage(connId, makeMessage(dir,f,cmdName)); pos+=2+compLen }
                    }
                }
                else -> { if (conn!=null && dir==LiveMessage.Direction.INBOUND){conn.inboundResyncBytes++; if(conn.inboundResyncBytes>MAX_RESYNC_BYTES){conn.inboundResyncBytes=0; return}}; pos++ }
            }
        }
        if (pos < raw.size) buffer.write(raw, pos, raw.size-pos)
    }

    private fun sendDataToApp(conn: SfaTcpConnState, data: ByteArray) {
        val pkt = com.nexora.hammerscale.net.PacketParser.buildIPv4TCPPacket(conn.dstIp, conn.srcIp, conn.dstPort, conn.srcPort, conn.localSeq, conn.remoteSeq, 0x18, 65535, data)
        conn.localSeq = (conn.localSeq + data.size.toLong()) and 0xFFFFFFFFL
        writeToVpn(pkt)
    }
    private fun sendSynAck(conn: SfaTcpConnState, remoteSynSeq: Long) {
        val pkt = com.nexora.hammerscale.net.PacketParser.buildIPv4TCPPacket(conn.dstIp, conn.srcIp, conn.dstPort, conn.srcPort, conn.localSeq, (remoteSynSeq+1L) and 0xFFFFFFFFL, 0x12, 65535, ByteArray(0))
        conn.localSeq = (conn.localSeq + 1L) and 0xFFFFFFFFL
        writeToVpn(pkt)
    }
    private fun sendAck(conn: SfaTcpConnState) {
        val pkt = com.nexora.hammerscale.net.PacketParser.buildIPv4TCPPacket(conn.dstIp, conn.srcIp, conn.dstPort, conn.srcPort, conn.localSeq, conn.remoteSeq, 0x10, 65535, ByteArray(0))
        writeToVpn(pkt)
    }
    private fun sendFin(conn: SfaTcpConnState) {
        val pkt = com.nexora.hammerscale.net.PacketParser.buildIPv4TCPPacket(conn.dstIp, conn.srcIp, conn.dstPort, conn.srcPort, conn.localSeq, conn.remoteSeq, 0x11, 0, ByteArray(0))
        writeToVpn(pkt)
    }
    private fun writeToVpn(data: ByteArray) { try { outStream.write(data) } catch (_: Exception) {} }
    private fun cleanup(connKey: String) {
        val conn = connections.remove(connKey) ?: return
        conn.status = SfaTcpStatus.CLOSED
        conn.outboundQueue.close()
        onStatusChange(conn.connId, ConnectionStatus.CLOSED)
        try { conn.channel?.close() } catch (_: Exception) {}
    }
    fun shutdown() {
        scope.cancel()
        connections.values.forEach { it.outboundQueue.close(); try{it.channel?.close()}catch(_:Exception){} }
        connections.clear()
    }
    // Simple injector for SFA dev testing (no battle patches)
    fun injectDirect(connId: String, data: ByteArray): String {
        val conn = connections[connId] ?: return "FAIL: no SFA conn $connId (${connections.size})"
        if (conn.status != SfaTcpStatus.ESTABLISHED) return "FAIL: status ${conn.status}"
        val ch = conn.channel ?: return "FAIL: channel null"
        if (!ch.isOpen || !ch.isConnected) return "FAIL: closed"
        return try {
            conn.writeLock.lock()
            try { val buf = ByteBuffer.wrap(data); while(buf.hasRemaining()) ch.write(buf); "SENT ${data.size}B" } finally { conn.writeLock.unlock() }
        } catch(e: Exception) { "FAIL: ${e.message}" }
    }
}
