# archive.bytes — decoding notes (FIXED)
Source: RTX Sf3 Project\gamedata\Resources\Configs\archive.bytes (307,594 B, plain ZIP PK\x03\x04)

Decoded in TWO layers as requested — not one dump:

## 1) Outer ZIP -> assets/archive/
- Extracted 43 entries from archive.bytes outer ZIP via Python zipfile
- Contents:
  - version.json (0.1.3.0.835-prod), server.json, config.json, sha, bundlesConfig.json (203k)
  - localization/English.xml + Russian.xml
  - game-settings/ (qualitySettings.json, fight_settings.yaml, tactics_settings.yaml, internalSettings.json, quests_triggers_result.yaml, splitmoves.bytes)
  - scripts/ (28 .js/.py files: battles.js 158k with 45 Battles entries RoundsToWin+Fights[], brawler.js brawlerRoundsToWin=2, roundrules.js, chapters.js, perkmodels.js 148k etc.)

## 2) Inner ZIP -> assets/archive/splitmoves/
- game-settings/splitmoves.bytes (3,324,993 B) is itself a ZIP (header PK\x03\x04, not AES-encrypted here)
- Separately decoded via zipfile -> assets/archive/splitmoves/
- Contains 283 YAML files: HEADER.yaml + split_0.yaml ... split_282.yaml
  - HEADER.yaml = Root SplitFiles lock table (SKELETON / PLAYER / SUPER_WEAPON / BattleType:Dojo etc.)
  - Each split_* = tactics result table / chronicle fight config (Locks on TagExists, Rule HasRule etc.)
  - These are the 'fight and chronicle configs' referenced

## Why two steps?
archivedec.py logic (KEY 08050674cc9ab867197f0cad55a770ca IV 653e0715236e0f734f1ebf64228b322d AES-CBC) applies to SF3 remote .enc flow (outer ZIP -> .enc -> inner ZIP). This SFA dump uses plain ZIP nesting instead, so we replicate the same two-stage extraction: outer archive.bytes then inner splitmoves.bytes, each to its own subfolder.

Counts: outer 43 -> total 331 files including inner 283 splits.
Verified: splitmoves.zip 283 entries, HEADER.yaml 100k, split_0.yaml 316k etc.

Decoded: 2026-09-02T16:31:17.6907705+05:30
