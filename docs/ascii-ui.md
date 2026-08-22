# ASCII UI Mockups

```text
NOVA GPS  SYS:#00af39c1  ONLINE
+----------------------+------------------------------------------+--------------------------+
| DEVICES              | MAP_PANEL                                | DIAGNOSTICS              |
| > Perez Demo Phone   | +--------------------------------------+ | $ diagnose system.health |
|   android-demo-001   | |     . . . terminal map grid . . .   | | exit=0 hash=b8a9f2...  |
|   phone              | |        X live marker                 | | nova-runner=ok         |
| Nova Van 02          | |                                      | | time=2026-05-30T...    |
|   vehicle            | +--------------------------------------+ +--------------------------+
+----------------------+------------------------------------------+--------------------------+
| ALERTS_LOGS                                                                              |
| REG  #07bb92ad Perez Demo Phone                                                          |
| EVT  #52a301ae {"event":"location.updated","device_type":"phone","source":"mobile"}       |
| CONS #aa18e522 consent.capture scope=live-location,history,alerts                         |
| DIAG #91cb0acf command_id=echo.hash output_hash=bd1a... exit=0                            |
+------------------------------------------------------------------------------------------+
```

```text
REGISTER TRACE
[REG] actor=dev-admin@nova.local device_type=phone identifier=android-demo-001 hash=#07bb92ad
[CONSENT] source=manual-admin scope=live-location,history,alerts proof_hash=2f739d...
[LOCATION] lat=37.77850 lon=-122.41560 source=mobile kafka=nova.locations hash=52a301...
[COMMAND] command_id=echo.hash args_hash=35df... output_hash=bd1a... sandbox=mock
```
