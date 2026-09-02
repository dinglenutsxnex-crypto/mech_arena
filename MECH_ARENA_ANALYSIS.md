# Mech Arena / HammerScale — PCAP + Protocol + Chronicle + Archive Deep-Dive

> Generated 2026-09-02 — **read-only analysis, no edits to `app/` were made.** All refs are `file:line`.

---

## 0. TL;DR

* **AWS game BS** is `ec2-18-139-63-38.ap-southeast-1.compute.amazonaws.com` (`18.139.63.38:443`, Singapore `ap-southeast-1`). It is discovered at runtime via `sfalb.nekki.com` (EU ALB  `63.188.28.186`) → DNS `CNAME sf-arena-octopus-alb-2031699450.eu-central-1.elb.amazonaws.com`.
* **Transport is NOT TLS** on the battle port despite `443`. Wireshark labels it `Continuation Data / SSL` by heuristic, but raw bytes are plain `0x01/0x02/0x03` frames (protobuf-wrapped, raw-DEFLATE optional). HammerScale captures them at the TUN layer (`TrafficVpnService`).
* **SFA-NEBU-1 handshake** is `counter=1, cmd=HANDSHAKE, params[1]=SFA-NEBU-1` → server replies with `uid=1950889, token=c9fb5c5d… , channel=256, endpoint=117.99.98.140:61259`.
* **Chronicle win** is a client-authoritative field patch: `finish_fight` / `event_battle_finish_fight` / `clan_finish_fight` / `brawler_finish` — the client tells the server `result=WIN, roundsToWin=N` (field 4/5/7). HammerScale either patches the byte in-flight (`PacketInjector.patchFinishFightToWin`) or synthesizes a whole `brawler_finish` envelope (`buildBrawlerFinishWin`).
* **`archive.bytes` / battles** — outer config ZIP → inner `.enc` (AES-128-CBC `08050674cc9ab867197f0cad55a770ca` / `653e0715236e0f734f1ebf64228b322d`, PKCS7) → inner ZIP `scripts/features/**`, `scripts/z_utils/**` → 4 JS-parsing strategies → `data/battles.json` (mapped into `R.raw.battles` AES-CTR encrypted).

---

## 1. App Structure

### 1.1 Gradle / Manifest

* `build.gradle:1` / `app/build.gradle:1` — AGP 8.2.2, Kotlin 1.9.22, SDK 34, Java 17, viewBinding, coroutines.
* `app/src/main/AndroidManifest.xml:13` — `com.nexora.hammerscale`, single launcher `MainActivity`, two `specialUse` FGServices (`TrafficVpnService`, `OverlayService`), `SYSTEM_ALERT_WINDOW`, `BIND_VPN_SERVICE`.
* Signed `release` with `hammerscale123` keystore (`app/build.gradle:11`).

### 1.2 Package Layout

```
app/src/main/java/com/nexora/hammerscale/
  App.kt                          — Application singleton
  AppState.kt:1                   — global viewModel holder
  BattleConfig.kt:14              — roundsToWin registry + AES-CTR loader
  MainActivity.kt:17              — VPN + overlay permission, play button
  OverlayService.kt:34            — floating UI, state machine (see §1.4)
  TrafficVpnService.kt:20         — TUN packet pump, duel-hijack loops
  SecurityModule.kt:8             — root/frida/emulator checks (no enforcement)
  LogDownloader.kt:12             — zip export of LiveMessages
  net/
    PacketParser.kt:47            — IPv4/TCP/UDP parse + build
    TcpHandler.kt:40              — TCP state, WS/SF3 split, all intercepts
    UdpHandler.kt:13              — DNS passthrough + generic UDP
    PacketInjector.kt:9           — brawler/win patchers + envelope builders
    GameProtocolParser.kt:9       — 0x01/0x02/0x03 → protobuf → GameEvent
    DnsPacket.kt                  — DNS A/CNAME encode/decode
  model/
    GameEvent.kt:6                — sealed events (label/detail)
    ConnectionEntry.kt:38         — conn row + LiveMessage list
    ConnectionViewModel.kt:14     — LiveData hub, counters, battle tracking
  ui/
    ConnectionAdapter.kt / LiveMessageAdapter.kt / SocketDetailActivity.kt
res/layout/
  layout_overlay.xml / layout_overlay_mini.xml / activity_main.xml
```

### 1.3 VPN Packet Path

`TrafficVpnService.kt:58` `startVpn()` → `Builder.addAddress("10.0.0.1") .addRoute("0.0.0.0") .addAllowedApplication("com.nekki.shadowfight3")` → `establish()` → `captureLoop()` (`PacketParser.parse` ) → `TcpHandler.handlePacket` / `UdpHandler.handlePacket`.  
`TcpHandler.kt:221` `handleSyn()` → `SynAck`, async `SocketChannel` to real dst, `writerLoop` + `readerLoop`.  
All outbound payloads are `sendAck`'d locally then optionally **patched** before `outboundQueue.trySend` to server. `injectDirect()` writes to `SocketChannel` directly (bypassing queue), `injectToServer()` queues.

### 1.4 Overlay State Machine

`OverlayService.kt:73` — `isUserMode` toggles dev (logs) vs user (switches). Observers:

* `eventObserver:93` / `winObserver` — feed `RecyclerView`.
* `battleObserver:123` — `currentBattleId` → `updateEventsPanel`.
* `clanRoundsObserver:129` — server `clan_rounds` auto-updates `roundsToWin` & re-arms.
* `battleSeqObserver:150` — multi-fight `BattleConfig.roundsFor(id, seq)` → per-sub-fight rounds.
* `gameEventsForTypeObserver:184` — `BattleStarted → arm after 3s`, `WinConfirmed → disarm + green flash`, `brawler_start → arm`.

UI panels: battle (ARM WIN), raid (ARM MAX DMG), brawler (ARM BRAWLER WIN), duel hijack win/loss (loop).

---

## 2. PCAP Decoding — `assets/PCAPdroid_02_Sept_14_06_58.pcapng`

### 2.1 File Meta

| field | value |
|---|---|
| path | `assets/PCAPdroid_02_Sept_14_06_58.pcapng` |
| size | 1 567 368 B (`wireshark_get_file_info`) |
| packets | 1 941, 1504 kB data, 682.4 s |
| encapsulation | Raw IP, iface Raw IP, capture device OPPO CPH2731 / Android 16 / PCAPdroid 1.9.1 |
| pcapng avg | 774 B/pkt, 2 pkt/s |
| SHA256 | `15aaaced5d1457b67077bc0323da00e51f48cf5268bac26e3f9f342b9c90b25a` |

`wireshark_quick_analysis` protocol split: `ip 1941, udp 214 (dns 112, classicstun 14, quic 88), tcp 1725 (tls 729 heuristic)`. Heuristic mislabels SF3 clear frames as TLS.

Top talkers (`wireshark_stats_endpoints`): `10.215.173.1` (local), `18.139.63.38` (167 pkts, 70 kB — **battle**), `63.188.28.186` (sfalb), `18.164.218.209` (cdn), `192.178.158.155` (googleads).

`sfa_chronicle_win.csv:28-29` confirms:

```
DNS sfalb.nekki.com → 61 B q, 303 B a
TLS sfalb 63.188.28.186:443 1381/5080 B 9/10 pkts
DNS ec2-18-139-63-38.ap-southeast-1.compute.amazonaws.com → 99/115 B
WebSocket 18.139.63.38:443 8195/62449 B 83/84 pkts 10.2 min  (stream 13)
STUN stuns.nekki.com 51.38.97.176:3478 216/96 B
```

### 2.2 AWS Server BS

* **Load balancer** — `sfalb.nekki.com` → `sf-arena-octopus-alb-2031699450.eu-central-1.elb.amazonaws.com` → `63.188.28.186` + `63.179.74.134` (EU-Central-1 ALB). Client hellos SNI=`sfalb.nekki.com` (`tshark tls.handshake.extensions_server_name`). Two connections: `57586` and `47536`, each TLS 1.3 (quick_analysis).
* **Battleserver** — DNS `ec2-18-139-63-38.ap-southeast-1.compute.amazonaws.com` → `18.139.63.38:443` (AP-Southeast-1 Singapore). **No SNI, no TLS** — SYN `#276`, continuation data immediately, **plain** `0x01` frames. So despite `443`, it is **not** `wss://` but raw TCP custom proto (port 443 is firewall-friendly). `sfa_chronicle_win.csv` tags it `WebSocket` because PCAPdroid infers from payload pattern, but tshark shows `Continuation Data` + `tcp.stream 13` raw protobuf.
* **STUN** — `stuns.nekki.com` → `51.38.97.176, 3.108.76.187:3478` classic STUN (`wireshark_analyze_protocol` `classicstun` 14 pkts).
* **CDN / telemetry** — `cdn.iads.unity3d.com`, `config.uca.cloud.unity3d.com`, `cdp.cloud.unity3d.com`, `report.appmetrica.yandex.net`, AppLovin, Fyber, Unity Ads — all TLS SNI-verified (see `tls_handshakes` list).

Flow: app → DNS sfalb → TCP+TLS sfalb → gets assignment (`HANDSHAKE` reply `117.99.98.140:61259` is the allocated host:port for this session, Singapore POP) → DNS ec2 Singapore → TCP battle channel.

### 2.3 SFA-NEBU Handshake

Hex dump (stream 13, tshark `tcp.payload`):

```
#279 OUT 011b0801120948414e445348414b451a0c0a0a5346412d4e4542552d31
#281 IN  014d0801120948414e445348414b451a3e08a98977122063396662356335643636356361322d30303164633461392d373639356532366118800222133131372e39392e39382e3134303a3631323539
```

`GameProtocolParser.kt:180` `extractPayload`:
* `0x01` = uncompressed, next byte = len (uint8), rest = protobuf body.
* `0x02` = compressed, next 4 LE = len, rest = raw DEFLATE.
* `0x03` = small compressed, next 1 = len, rest = raw DEFLATE.

`readProtoFields` (`GameProtocolParser.kt:352`): varint tag = `(field<<3|wire)`, wire `0=varint,2=len-delim`. Envelope (`parseEnvelope:207`):

```
field 1: counter (varint)
field 2: command (bytes / string)
field 3: params (bytes, inner protobuf)
```

**Outbound** `HANDSHAKE` (`GameProtocolParser.kt:213`):

```
counter=1
cmd="HANDSHAKE"
params → readProtoFields → field 1 = "SFA-NEBU-1"   // server selector string
```

Event `HandshakeOut("SFA-NEBU-1")` (`GameEvent.kt:12`).

**Inbound** `HANDSHAKE` (`GameProtocolParser.kt:221`):

```
counter=1
cmd="HANDSHAKE"
params → field1=1950889 (int assignment id?)
        field2="c9fb5c5d665ca2-001dc4a9-7695e26a" (session token / device id)
        field3=256   // channel? shard?
        field4="117.99.98.140:61259"  // allocated game host
```

Event `HandshakeIn(token)` where token = `field2[2]` inside topological `field2` blob (`GameProtocolParser.kt:222`). CSV last-seen confirms this is the long-lived socket (673 s).

### 2.4 Next: LOGIN → Join Zone → GetPlayer → Lobby

All subsequent commands are inside same TCP stream, multiplexed by `counter` (monotonic `AtomicLong` `ConnectionViewModel.kt:33`). HammerScale tracks `nextInjectCounter = max(outboundCounter, injectCounter)+1` (`ConnectionViewModel.kt:36`) so injected forks never collide.

| # (frame) | dir | cnt | command | notes |
|---|---|---|---|---|
| 284 | OUT | 2 | `LOGIN` (0x02 comp) | `params: 1=7, 2=JSON {"login":"ad456b33da81cefd","password":"70fb6aad1e2d0af8…"}, 3=token {"t":"4/0ATs…"}, 4=platform meta` (`GameProtocolParser.kt:324` JSON scan) |
| 301 | IN | 2 | `LOGIN` | empty ack → `LoginIn()` |
| 302 | IN | — | `join_zone` | `params[1,2,5]` (zone join) — server auto |
| 304 | OUT | 3 | `ping` | `params[1]=timestamp blob, 2=net_data "26210F1C26DE9D30…"` (keepalive, `GameProtocolParser.kt:410` net_data captured for synthetic pings) |
| 306 | IN | 3 | `ping` | echoed |
| 308 | OUT | 4 | `get_player` | large `params[5]` JSON device blob `{"device":"OPPO CPH2731","OS":"Android OS 16 …"}` |
| 310 | IN | 4 | `get_player` | 2921 B blob, fields `1=player blob, 2=profile, 3=…, 5=counter, 6=…` |
| 357 | OUT | 5 | `get_accounts` | `params[1]=0x0e0d` |
| 377 | IN | 5 | `get_accounts` | `a_5393240314574634243, 730465` (account id) |
| 844 | OUT | 6 | `get_brawler_pool` | bare (no params) |
| 846 | IN | 6 | `get_brawler_pool` | `field1=1138, field2=507 B pool blob` |
| 848 | OUT | 7 | `get_leaderboard` | `params[1]=08 01 28 01 …` |
| 857 | OUT | 8 | `get_leaderboard` | second shard |
| 1150 | OUT | 9 | `roguelike_enter_chapter` | chapter 1-? |
| 1154 | IN | 9 | `roguelike_enter_chapter` | ack `field1=1139, 56 B` |
| 1570…1797 | OUT/IN | 10-30 | `ping` **×46** | ~30 s interval keepalives (odd counters are client, even server echo). `TcpHandler` `hijackBlockOutgoing` can suppress these when hijacking. |
| 1800 | OUT | 31 | `process_offline_batch` | batch flush after idle |
| 1811 | IN | — | `quest_refresh_event` | server push |
| 1814 | IN | — | `promo_offers_update_event` | server push |
| 1842 | OUT | 32 | `get_brawler_pool` | re-poll |
| 1844 | IN | 32 | `get_brawler_pool` | `1153, 499 B` |
| 1846 | OUT | 33 | `get_leaderboard` | |
| 1856 | OUT | 34 | `get_leaderboard` | |

Counts: `ping 46, get_brawler_pool 4, get_leaderboard 4, HANDSHAKE 2, LOGIN 2, get_accounts 2, get_player 2, roguelike 2, process_offline_batch 2, join_zone 1, quest_refresh 1, promo 1` (see script `decode_pcap2.py`).

Every lobby action is a pair `OUT cnt=N` → `IN cnt=N`. `ping` carries `net_data` which HammerScale stashes (`ConnectionViewModel.kt:125` `lastPingNetDataBytes` = `GameProtocolParser.extractPingNetData` field 2) for building synthetic pings (`PacketInjector.buildPing`).

> **To reproduce decode**: `tshark -r PCAP… -Y "ip.addr==18.139.63.38" -T fields -e frame.number -e tcp.payload` → hex → deflate if 0x02/0x03 → `readProtoFields` → command at field 2. Script `assets/archivedec.py`-style or `decode_pcap2.py` in `/tmp` implements it.

---

## 3. Chronicle Win — How a Win Is Sent

### 3.1 Command taxonomy (`GameProtocolParser.kt:11`)

```kt
BATTLE_COMMANDS = brawler_start/finish, finish_fight,
  refresh_battles, cheat_generate_battle, clan_*,
  start_fight, get_battles,
  event_battle_start_fight / _finish_fight,
  clan_start/finish, raid_fight_finish, ping …

BATTLE_START = start_fight | event_battle_start_fight | clan_start_fight
BATTLE_END   = finish_fight | brawler_finish | event_battle_finish_fight | clan_finish_fight
```

Lobby `battles` are started via `*_start_fight` (carry `battleId` at `params[1]` long 10k…999M). The **chronicle / story raid** path is `event_battle_start_fight` / `_finish_fight` (`GameProtocolParser.kt:76` `tryExtractFinishFight` only fires on `event_battle_finish_fight`), `raid_fight_*`.

### 3.2 Normal flow (no cheat)

```
OUT event_battle_start_fight  #12345  (BattleStarted event)
<-  IN  event_battle_start_fight  seq=0  (server tells HammerScale battleSeq via extractBattleSeqFromServerStart:95)
... player fights ...
OUT event_battle_finish_fight #12345  params: 1=battleId, 4=rounds_won?, 5=rounds_total?, 7=?
 IN event_battle_finish_fight  (WinConfirmed if params==null → server confirmed)  GameEvent.kt:19
```

For `clan`, server also embeds `clan_rounds` via `extractClanRoundsFromStartResponse:162` (field `f1b[10]` 1..10) which directly sets `OverlayService.clanRoundsObserver → roundsToWin`.

### 3.3 Cheat path — field-level patch (`PacketInjector.kt:106`)

`patchFinishFightToWin(data, roundsToWin)` assumes `0x01` uncompressed frame. Walk:

```
proto field 3 = params (len varint, assume 1-byte — strict)
params fields: 4 = result (0=loss,1=win), 5 = roundsToWin, 7 = roundsToWin copy
```

* If `field5` exists: overwrite `field4=1, field5=roundsToWin, field7=roundsToWin` in-place (3 byte edits).
* If `field5` missing: splice `0x28 <rounds>` (field 5 varint) after `protoEnd`, bump both length bytes (`data[1]` frameLen, `paramsLenBytePos`) -> grows frame.

`TcpHandler.kt:294` arms it:

```kt
if (interceptArmed.get() && tryExtractFinishFight(payload)!=null) {
  interceptArmed.set(false)
  patched = patchFinishFightToWin(payload, interceptRounds.get())
}
```

Same for `clan` (`tryExtractClanFinishFight:150`, `patchFinishFightToWin` reused) and `raid` (`tryExtractRaidFightFinish`, `patchRaidFightFinishToMaxDamage:199` injects `float 1.0` via `0x15 00 00 80 3F` or overwrites `field2 float`).

### 3.4 Brawler path — full envelope rebuild

Brawler is **PvP** (`brawler_start`/`brawler_finish`). Unlike chronicle, its finish payload is complex (enemy blob + stats). HammerScale **rebuilds** the packet (`PacketInjector.kt:83`):

```kt
buildBrawlerFinishWin(enemyBlob, counter) = envelope("brawler_finish",
  params { field1=enemyBlob, 2=1 (result WIN), 3=2 (wonRounds),
           4× round entries 08 03 10 01 etc, 5=2, 6=WIN_ITEMS, 7=WIN_STATS })
```

`WIN_ITEMS` = 4 items `d1 0c, d2 0c, d9 34×2`), `WIN_STATS` = 38 B stats (`08 02 10 1f …`), `BRAWLER_WIN_ROUND_ENTRIES` = 5 entries (`GameProtocolParser:11`). Loss variant (`buildBrawlerFinishLoss:96`) sends `0,0` no items.

Two modes:

* **Intercept** (`patchBrawlerFinishToWin:396` / `patchInboundBrawlerFinishToWin:275`) — find `brawler_finish` inside a larger TCP segment (0x01/0x02/0x03), inflate, `tryPatchBrawlerProto:447` locates `counter`, `paramsBytes`, then re-emits a clean envelope. Outbound path patches client loss → win; inbound path (readerLoop `TcpHandler.kt:409`) patches server loss → win if client missed.
* **Duel hijack loop** (`TrafficVpnService.kt:215` `runDuelHijack`) — fully synthetic: `buildBrawlerStart(counter)` (empty params) → wait for server `brawler_start` reply `extractBrawlerStartEnemyBlob:397` (params[1]) via `sniffDuelHijack:160` callback → `buildBrawlerFinishWin(blob, nextCounter)` → repeat. `hijackBlockOutgoing=true` suppresses real client packets while looping. Loss loop (`runDuelHijackLoss:288`) mirrors with `buildBrawlerFinishLoss`.

`OverlayService` wires the toggle: `sw_brawler` arms on next `brawler_start`, `btn_brawler_win` / `sw_duel_hijack` arm directly, with logging `HammerBrawler` / `HammerDuel`.

### 3.5 RoundsToWin sourcing

`BattleConfig.kt:24` `roundsFor(battleId, subIdx)`:

* `Int` → single fight
* `List<Int>` → multi-fight (skeleton, see §4), indexes by `battleSeq` from server start reply (`OverlayService.battleSeqObserver:150` reads `field bc[3]` subIndex).

Auto-populated on `currentBattle` change (`OverlayService.updateEventsPanel:438` pulls `BattleConfig.roundsFor(id)`), and on clan start (`clanRoundsObserver`).

---

## 4. `archive.bytes` — The Fight & Chronicle Configs

### 4.1 Location & Crypto

User notes: SF3 apk assets contain `archive.bytes` (ZIP-in-ZIP, AES). Local test decode is `assets/archivedec.py`. Keys match `scripts/extract_battles.py:49`:

```
KEY = 08050674cc9ab867197f0cad55a770ca
IV  = 653e0715236e0f734f1ebf64228b322d   // CBC
```

`archivedec.py:16` `dec_data`:

```py
Cipher(AES(CBC(IV))).decryptor() → plain[:-pad]  # PKCS7 1..16
enc_data  # padder + encryptor
```

On device paths `/storage/emulated/0/archive.bytes/*.enc` → `/decrypted_archives/*.zip`, but CI uses `extract_battles.py` remote fetch:

```
BALANCE_URL = https://sfxlbalt.nekki.com:9043/balance?w=IN&fv=1.485...&p=Android
→ JSON { version:{cur, url} }
→ download outer ZIP → find .enc (shortest name) → aes128_cbc_decrypt → inner ZIP ( ~ 1-2 MB)
```

`BattleConfig.kt:91` per-battle resource variant uses **different** cipher: `AES/CTR/NoPadding` with `KEY` same, `NONCE=653e0715236e0f73` (8 B, reused as IV, CTR), loaded from `R.raw.battles` (`BattleConfig.loadAsync:52`).

### 4.2 Inner ZIP layout

EOCD parse (`extract_battles.py:157`), entries:

* `scripts/features/**.js` — event templates, chapter missions, raid
* `scripts/z_utils/**.js` — utility templates
* `scripts/features/events/templates/skeletons/*.js` — skeleton_danger / incremental
* `scripts/features/events/templates/skins/**/{*_skin.js,_intro_battles.js}` — narrative skins
* `version.json`

### 4.3 Four parsing strategies → `data/battles.json`

`parse_all_battles:429` yields `{ battledId: rounds | [rounds...] }` (1536 entries in current `data/battles.json:3` `1.45.0.121.16708-prod`).

1. **Cross-file skin intro** (highest priority) — `frost_skin`, `circus_skin` etc. `*_intro_battles.js` defines `intro_KEY: {RoundsToWin:N}`, `*_skin.js` maps `intro_KEY: prepareArchBattle(template,{ID:NNNNN})` → join → `(ID,N)`. Needs `_normalize_intro_key`.

2. **Direct scan** per JS file:
   * Long window 2000 chars `ID → DefaultTemplate → Fights:[{RoundsToWin}]` → if `Fights` array found, `rounds_list = findall RoundsToWin` → multi-value → `list`, else single. Else short 500 window `ID → RoundsToWin` (SideBattleArchetype).

3. **__assign chain** — `var BASE={RoundsToWin:N}` → `PROP: __assign({},BASE)` → `PROP→rounds`, then `__assign({ID},TEMPLATE.PROP)` → 2-level.

4. **Skeleton/meta** — `skeleton_danger.js` key→rounds via tight `key:__assign({…RoundsToWin:N…})` per key window, plus infer from skin block `roundCountSettings.roundsToWins` (list vs single) or `fights` count `ceil(N/2)`. Join with `*_skin.js` `prepareArchBattle` non-intro keys.

Output `data/battles.json:4` example:

```json
{"10022":[3,3], "10023":[3,1,3], "10113":5, "3101111":[2,2,2,2], "3002911":[2,3,2,4,3,3,4,2,5,3] }
```

Interpreted by `BattleConfig.kt:24` `roundsFor`/`totalFightsFor`/`isMultiFight`.

### 4.4 How to reproduce locally

```bash
python scripts/extract_battles.py                    # live fetch
python scripts/extract_battles.py --local-zip inner.zip  # offline
# or decrypt a dumped archive.bytes dump
python assets/archivedec.py   # expects /storage/emulated/0/archive.bytes on device
```

---

## 5. Full Command Order (this capture)

See `decode_pcap2.py` reconstruction (82 segments, 167 pkts, stream 13). Ordered by `frame.number` (time). Counter is strict +1; direction matters — 46 are `ping` heartbeats.

| step | time (IST) | dir | cnt | cmd | params |
|---|---|---|---|---|---|
| 1 | 14:07:12.966 | OUT | 1 | HANDSHAKE | SFA-NEBU-1 |
| 2 | 14:07:13.060 | IN | 1 | HANDSHAKE | token + host |
| 3 | 14:07:13.087 | OUT | 2 | LOGIN | login+pass+platform |
| 4 | 14:07:14.583 | IN | 2 | LOGIN | OK |
| 5 | | IN | — | join_zone | auto |
| 6 | 14:07:14.616 | OUT | 3 | ping | net_data 26210F… |
| 7 | 14:07:14.708 | IN | 3 | ping | echo |
| 8 | 14:07:14.752 | OUT | 4 | get_player | device OPPO CPH2731 |
| 9 | 14:07:14.951 | IN | 4 | get_player | blob |
| 10 | 14:07:15.627 | OUT | 5 | get_accounts | 0x0e0d |
| 11 | 14:07:15.797 | IN | 5 | get_accounts | 730465 |
| 12 | 14:07:19.568 | OUT | 6 | get_brawler_pool | — |
| 13 | 14:07:19.687 | IN | 6 | get_brawler_pool | 1138 / 507 B |
| 14 | 14:07:20.439 | OUT | 7 | get_leaderboard | shard 1 |
| 15 | 14:07:20.775 | OUT | 8 | get_leaderboard | shard 2 |
| 16 | 14:07:27.836 | OUT | 9 | roguelike_enter_chapter | c 1 |
| 17 | 14:07:27.942 | IN | 9 | roguelike_enter_chapter | 1139 |
| 18-63 | 14:07:44–17:49 | OUT/IN | 10-30 | ping ×21 pairs | 30 s interval |
| 64 | 14:18:09.870 | OUT | 31 | process_offline_batch |  |
| 65 | 14:18:10.201 | IN | — | quest_refresh_event | push |
| 66 | 14:18:10.203 | IN | — | promo_offers_update_event | push |
| 67 | 14:18:10.206 | IN | 31 | process_offline_batch |  |
| 68 | 14:18:18.210 | OUT | 32 | get_brawler_pool | — |
| 69 | 14:18:18.310 | IN | 32 | get_brawler_pool | 1153 / 499 B |
| 70 | 14:18:18.389 | OUT | 33 | get_leaderboard | |
| 71 | 14:18:18.609 | OUT | 34 | get_leaderboard | |
| 72 | 14:18:19.220 | OUT | 35 | ping |  |
| 73 | 14:18:19.330 | IN | 35 | ping |  |

*No `finish_fight`/`brawler_finish` appears here — lobby idle. To see a win, trigger a story battle (`roguelike_enter_chapter` / event) then `event_battle_finish_fight`; HammerScale will show `## WIN CONFIRMED` via `TcpHandler` patch.*

---

## 6. Security / Notes

* `SecurityModule.kt:17` claims `isDeviceCompromised` but is **not enforced** anywhere (only `getDetectedThreats` logged).
* All crypto keys are **hardcoded** in app & scripts — ship-level.
* `TrafficVpnService.TARGET_PACKAGE = "com.nekki.shadowfight3"` (`TrafficVpnService.kt:25`) but CSV `PackageName = com.nekki.shadowfightarena` — alias / internal name mismatch, but `addAllowedApplication` tolerates missing (`:68` try/catch).
* STUN is plaintext classic STUN to `3.108.76.187`.

---

## 7. How to extend

* **Add chronicle IDs** — run `python scripts/extract_battles.py` then `BattleConfig` auto-loads `R.raw.battles` at overlay start.
* **Sniff new win field** — log `hexDump` (`ConnectionEntry.kt:25`) before/after patch, compare `field4/5/7`.
* **Repack archive** — `archivedec.py MODE=encrypt` → `/storage/emulated/0/repacked_archives/*.enc`.

*All edits deferred per request — this doc is shareable, `app/` untouched.*
