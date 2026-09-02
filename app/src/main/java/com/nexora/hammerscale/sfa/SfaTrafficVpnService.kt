package com.nexora.hammerscale.sfa

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.nexora.hammerscale.MainActivity
import com.nexora.hammerscale.R
import com.nexora.hammerscale.model.*
import com.nexora.hammerscale.net.PacketParser
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.nio.ByteBuffer

/**
 * SFA copy of TrafficVpnService — independent for SFA (com.nekki.shadowfightarena).
 * Reuses PacketParser, but uses SfaTcpHandler/SfaUdpHandler/SfaGameProtocolParser.
 * No SF3 battle logic.
 */
class SfaTrafficVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.nexora.hammerscale.sfa.START_VPN"
        const val ACTION_STOP  = "com.nexora.hammerscale.sfa.STOP_VPN"
        const val TARGET_PACKAGE = "com.nekki.shadowfightarena"
        const val CHANNEL_ID = "hammerscale_vpn_sfa"
        const val NOTIF_ID = 1002
        const val VPN_ADDRESS = "10.0.0.2"
        const val VPN_ROUTE   = "0.0.0.0"
        @Volatile var instance: SfaTrafficVpnService? = null
    }
    private var vpnInterface: ParcelFileDescriptor? = null
    private var captureJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var tcpHandler: SfaTcpHandler? = null
    private var udpHandler: SfaUdpHandler? = null
    val viewModel: SfaConnectionViewModel by lazy { SfaAppState.viewModel }

    override fun onCreate() { super.onCreate(); instance=this; createNotificationChannel() }
    override fun onStartCommand(intent: Intent?, flags:Int, startId:Int): Int {
        return when(intent?.action){ ACTION_STOP -> {stopVpn(); START_NOT_STICKY} else -> {startVpn(); START_STICKY} }
    }
    private fun startVpn(){
        try{
            val builder = Builder().setSession("HAMMERSCALE-SFA").addAddress(VPN_ADDRESS,24).addRoute(VPN_ROUTE,0).addDnsServer("8.8.8.8").addDnsServer("8.8.4.4").setMtu(1500)
            try{ builder.addAllowedApplication(TARGET_PACKAGE) }catch(_:Exception){}
            vpnInterface = builder.establish()
            val fd = vpnInterface?.fileDescriptor ?: return
            tcpHandler = SfaTcpHandler(
                vpnService=this, vpnFd=fd,
                onConnectionEvent={e->viewModel.addOrUpdateConnection(e)},
                onMessage={id,msg->viewModel.addMessage(id,msg)},
                onStatusChange={id,st->viewModel.updateConnectionStatus(id,st)},
                onWebSocket={id->viewModel.markAsWebSocket(id)}
            )
            udpHandler = SfaUdpHandler(
                vpnService=this, vpnFd=fd,
                onConnectionEvent={e->viewModel.addOrUpdateConnection(e)},
                onMessage={id,msg->viewModel.addMessage(id,msg)},
                onStatusChange={id,st->viewModel.updateConnectionStatus(id,st)}
            )
            captureJob = scope.launch { captureLoop(fd) }
            viewModel.setVpnRunning(true)
            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) startForeground(NOTIF_ID, buildNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(NOTIF_ID, buildNotification())
        }catch(e:Exception){ Log.e("SfaTrafficVpnService","Failed start",e); stopVpn() }
    }
    private suspend fun captureLoop(fd: java.io.FileDescriptor){
        val input=FileInputStream(fd); val buf=ByteBuffer.allocate(32767)
        while(currentCoroutineContext().isActive){
            try{
                buf.clear()
                val len=withContext(Dispatchers.IO){ input.read(buf.array()) }
                if(len<=0){ delay(1); continue }
                buf.limit(len)
                val packet=PacketParser.parse(buf) ?: continue
                when(packet.ip.protocol){ PacketParser.PROTO_TCP -> tcpHandler?.handlePacket(packet); PacketParser.PROTO_UDP -> udpHandler?.handlePacket(packet) }
            }catch(e:Exception){ if(!currentCoroutineContext().isActive) break; delay(10) }
        }
    }
    fun stopVpn(){
        captureJob?.cancel(); tcpHandler?.shutdown(); udpHandler?.shutdown(); vpnInterface?.close(); vpnInterface=null; viewModel.setVpnRunning(false); stopForeground(true); stopSelf()
    }
    override fun onRevoke(){ stopVpn(); super.onRevoke() }
    override fun onDestroy(){ stopVpn(); scope.cancel(); instance=null; super.onDestroy() }
    private fun createNotificationChannel(){
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.O){
            val channel=NotificationChannel(CHANNEL_ID,"HAMMERSCALE SFA",NotificationManager.IMPORTANCE_LOW).apply{description="SFA traffic VPN"; setShowBadge(false)}
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }
    private fun buildNotification(): Notification{
        val stopIntent=Intent(this,SfaTrafficVpnService::class.java).apply{action=ACTION_STOP}
        val stopPending=PendingIntent.getService(this,0,stopIntent,PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val openIntent=PendingIntent.getActivity(this,0,Intent(this,MainActivity::class.java),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this,CHANNEL_ID).setContentTitle("HAMMERSCALE SFA Active").setContentText("Monitoring: $TARGET_PACKAGE").setSmallIcon(android.R.drawable.ic_dialog_info).setContentIntent(openIntent).addAction(android.R.drawable.ic_delete,"Stop",stopPending).setOngoing(true).build()
    }
}
