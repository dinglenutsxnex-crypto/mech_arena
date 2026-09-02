package com.nexora.hammerscale

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import com.nexora.hammerscale.databinding.ActivityMainBinding
import com.nexora.hammerscale.model.ConnectionViewModel
import com.nexora.hammerscale.model.ConnectionViewModelFactory
import com.nexora.hammerscale.sfa.SfaAppState
import com.nexora.hammerscale.sfa.SfaTrafficVpnService

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var viewModel: ConnectionViewModel
    // SFA viewModel is singleton via SfaAppState
    private val sfaViewModel get() = SfaAppState.viewModel

    private val VPN_REQUEST_CODE     = 100
    private val OVERLAY_REQUEST_CODE = 101
    private val VPN_REQUEST_CODE_SFA = 102

    private enum class GameTarget { SF3, SFA }
    private var pendingGame: GameTarget = GameTarget.SF3

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        viewModel = ViewModelProvider(this, ConnectionViewModelFactory())[ConnectionViewModel::class.java]

        binding.btnPlay.setOnClickListener {
            pendingGame = GameTarget.SF3
            if (viewModel.vpnRunning.value == true || sfaViewModel.vpnRunning.value == true) {
                stopAllVpn()
            } else {
                requestVpnPermission(GameTarget.SF3)
            }
        }

        binding.btnPlaySfa.setOnClickListener {
            pendingGame = GameTarget.SFA
            if (sfaViewModel.vpnRunning.value == true || viewModel.vpnRunning.value == true) {
                stopAllVpn()
            } else {
                requestVpnPermission(GameTarget.SFA)
            }
        }

        binding.tvDiscordLink.setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://discord.gg/AW9vGhVA2j")).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            })
        }

        viewModel.vpnRunning.observe(this) { running ->
            binding.btnPlay.setImageResource(
                if (running) android.R.drawable.ic_media_pause
                else R.drawable.ic_play
            )
            updateSfaButton()
        }
        sfaViewModel.vpnRunning.observe(this) { running ->
            binding.btnPlaySfa.setImageResource(
                if (running) android.R.drawable.ic_media_pause
                else R.drawable.ic_play
            )
            updateSf3Button()
        }

        if (!Settings.canDrawOverlays(this)) {
            requestOverlayPermission()
        }
    }

    private fun updateSf3Button() {
        // dim SF3 button when SFA is active
        val sfaRunning = sfaViewModel.vpnRunning.value == true
        binding.btnPlay.alpha = if (sfaRunning) 0.4f else 1.0f
        binding.btnPlay.isEnabled = !sfaRunning
    }
    private fun updateSfaButton() {
        val sf3Running = viewModel.vpnRunning.value == true
        binding.btnPlaySfa.alpha = if (sf3Running) 0.4f else 1.0f
        binding.btnPlaySfa.isEnabled = !sf3Running
    }

    private fun startOverlay(game: GameTarget) {
        // Pass game hint via intent extra so Overlay can show correct mode
        startService(Intent(this, OverlayService::class.java).apply {
            action = OverlayService.ACTION_START
            putExtra("game", game.name)
        })
        Handler(Looper.getMainLooper()).postDelayed({
            launchTargetApp(game)
        }, 500)
    }

    private fun stopOverlay() {
        startService(Intent(this, OverlayService::class.java).apply {
            action = OverlayService.ACTION_STOP
        })
    }

    private fun requestOverlayPermission() {
        val intent = Intent(
            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
            Uri.parse("package:$packageName")
        )
        startActivityForResult(intent, OVERLAY_REQUEST_CODE)
    }

    private fun launchTargetApp(game: GameTarget) {
        val pkg = when (game) {
            GameTarget.SF3 -> TrafficVpnService.TARGET_PACKAGE
            GameTarget.SFA -> SfaTrafficVpnService.TARGET_PACKAGE
        }
        val intent = packageManager.getLaunchIntentForPackage(pkg)
        if (intent != null) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
        }
    }

    private fun requestVpnPermission(game: GameTarget) {
        pendingGame = game
        val code = if (game == GameTarget.SFA) VPN_REQUEST_CODE_SFA else VPN_REQUEST_CODE
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, code)
        else startVpn(game)
    }

    @Deprecated("Deprecated")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            VPN_REQUEST_CODE -> if (resultCode == Activity.RESULT_OK) startVpn(GameTarget.SF3)
            VPN_REQUEST_CODE_SFA -> if (resultCode == Activity.RESULT_OK) startVpn(GameTarget.SFA)
            OVERLAY_REQUEST_CODE -> {}
        }
    }

    private fun startVpn(game: GameTarget = pendingGame) {
        when (game) {
            GameTarget.SF3 -> startService(Intent(this, TrafficVpnService::class.java).apply { action = TrafficVpnService.ACTION_START })
            GameTarget.SFA -> startService(Intent(this, SfaTrafficVpnService::class.java).apply { action = SfaTrafficVpnService.ACTION_START })
        }
        if (Settings.canDrawOverlays(this)) {
            Handler(Looper.getMainLooper()).postDelayed({
                startOverlay(game)
            }, 300)
        }
    }

    private fun stopVpn() { stopAllVpn() }
    private fun stopAllVpn() {
        stopOverlay()
        startService(Intent(this, TrafficVpnService::class.java).apply { action = TrafficVpnService.ACTION_STOP })
        startService(Intent(this, SfaTrafficVpnService::class.java).apply { action = SfaTrafficVpnService.ACTION_STOP })
    }
}
