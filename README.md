# SIGMA_POC — L3 Threat-Hunt Abstraction Layer (Windows)

Author: **Ala Dabat**  
Scope: **Sigma proof-of-concept** that abstracts my production KQL hunt packs into portable detection logic.  
Audience: Hiring managers, Detection Engineers, Threat Hunters (L2.5/L3).

---

## Why Sigma exists in this repo (and why my production logic is still KQL)

Sigma is the **interoperability layer**. It’s how detection logic gets shared across platforms.

My production hunts (KQL for Sentinel + MDE) are built around:
- **time-window correlation** (entity chaining across 5m / 30m / 4h buckets)
- **weighted scoring models** (distinct-signal scoring, capped accumulation, rarity gates)
- **table-specific enrichments** (org prevalence, signer context, cross-table joins)

Sigma can express **pattern logic** extremely well, but it generally cannot express:
- score thresholds like `Score > 80 in 4h`
- rarity-aware scoring
- multi-table joins (process + registry + network + image-load) as a single “native rule”
- “distinct signal capping” aggregation (max signal instead of sum of events)

So this folder proves I can:
- **engineer portable logic**
- **name and stage detections like an L3 hunter**
- **document correlation requirements like an engineer**
- while keeping the *true production implementation* optimized in KQL.

---

## Folder layout

SIGMA_POC/
README.md
rules/
c2_lateral/
lolbins/
wmi/
identity/
persistence/
sideloading/


---

## Detection philosophy (L3)

### 1) Distinct-signal scoring > event volume
Many environments generate legitimate noise (SCCM/MECM, admin scripts, enterprise agents).  
My KQL hunts cap score per signal type (e.g., max DLL-load score) instead of summing volumes.

In Sigma, that becomes:
- **separate stage rules** (subtrate / persistence / remote exec / target effect)
- “correlation-ready” naming and tags
- explicit tuning guidance per stage

### 2) Attack chains are modeled as Source vs Target
Lateral movement is not “one host”; it’s:
- **Host A (source)** runs remote exec tradecraft
- **Host B (target)** exhibits the execution effect

My Sigma rules preserve this separation:
- `..._source.yml` vs `..._target.yml`
- correlation note: join on time window + account + target host/IP when available

### 3) Substrate / blind-spot hunting
High-end tradecraft avoids process creation.
Example: **WMI ActiveScriptEventConsumer** executing in-memory inside `scrcons.exe`.
So I hunt the substrate:
- `scrcons.exe` loading scripting engines (`vbscript.dll`, `jscript.dll`, `scrobj.dll`)
- `scrcons.exe` making HTTP/S connections
- WBEM/WMI registry artifacts

---

## Rule inventory (Sigma POC)

| Rule Group | Sigma File | Purpose | Primary MITRE |
|---|---|---|---|
| KEEP | `c2_lateral/win_pipe_c2_lateral_high_fidelity.yml` | Named Pipe C2 / lateral movement indicators | T1071, T1021, T1047 (adjacent), T1570 |
| KEEP | `lolbins/win_lolbin_dotnet_toolchain_abuse.yml` | .NET build/compile abuse (msbuild/csc/installutil/regasm/pcwrun) | T1127, T1218, T1059 |
| ADD | `wmi/win_wmi_remoteexec_source.yml` | WMI remote exec “source” behavior (`/node` + `process call create`) | T1047, T1021 |
| ADD | `wmi/win_wmi_remoteexec_target.yml` | WMI remote exec “target effect” (`wmiprvse.exe` spawning LOLBins) | T1047 |
| ADD | `wmi/win_wmi_processless_persistence_scrcons_substrate.yml` | WMI fileless persistence substrate (script engine DLL loads) | T1546.003 |
| ADD | `wmi/win_wmi_processless_persistence_scrcons_network.yml` | `scrcons.exe` network beacons (rare) | T1546.003, T1071 |
| ADD | `identity/win_kerberoasting_rc4_tgs.yml` | Kerberoast indicator (RC4 TGS requests) | T1558.003 |
| ADD | `sideloading/win_dll_sideload_search_order_hijack_chain.yml` | DLL sideload/search-order hijack chain signals | T1574.001 |
| ADD | `persistence/win_registry_persistence_signal_based_plus_wmi.yml` | Run keys/IFEO/COM/LSA + WBEM/WMI artifacts | T1547.001, T1546.012, T1546.003 |

> **Note:** The Sigma layer is *stage rules*. In production KQL, these stages are chained with scoring + entity bucketing.

---

## Correlation guidance (how to operationalize Sigma in a SIEM)

Sigma rules here are written as:
- **stage detections** (high-fidelity signals)
- intended to be correlated by backend engines, e.g.:
  - Elastic EQL / Event Correlation
  - Splunk correlation searches
  - Sentinel analytic rules (scheduled rule joins)
  - custom UEBA pipelines

Recommended correlation patterns:

### WMI Remote Exec chain
- Alert if **Source** stage OR **Target** stage triggers (each is high fidelity)
- Correlate source→target when possible using:
  - `/node:<target>` extraction
  - matching accounts
  - close time window (5–15 minutes)

### WMI Process-less persistence
- Substrate (`scrcons` + scripting DLL loads) alone is a strong signal
- Add severity if:
  - network beacons present
  - WBEM/WMI persistence keys modified
  - suspicious WQL filters / consumer names observed (platform-dependent telemetry)

### Kerberoasting
- Sigma cannot baseline-count by itself.
- Use this rule to surface **RC4 TGS usage** as an indicator.
- Correlate with SIEM aggregation:
  - unusual requester host(s)
  - spikes per service account
  - repeated activity across many SPNs

### DLL sideload chain
- Sigma detects **signal fragments**:
  - DLL loads from user-writable paths
  - suspicious loader execution context
  - persistence registry writes (if available)
- Production KQL uses joins + timing windows.

---

## Testing & validation

Suggested validation workflow:
- Atomic Red Team / bespoke simulation (safe lab only)
- Verify telemetry prerequisites:
  - Sysmon for Named Pipes / ImageLoad / NetworkConnect where needed
  - Security auditing for 4769 (Kerberos TGS)
  - Registry set telemetry from EDR/Sysmon

---

## Tuning principles (what I expect in a real tenant)

- Always baseline **known enterprise tools** (SCCM/MECM, Intune agents, deployment systems)
- Treat “rare + high intent” as the gating strategy:
  - weird parent chains
  - user-writable paths
  - signed loader + suspicious module path (in KQL)
- Maintain allowlists as watchlists in production (publisher/process hashes)

---

## MITRE mapping summary

- **Named Pipes / C2 / lateral movement**: T1071 (C2), T1021.* (lateral movement), T1570 (lateral tool transfer, adjacent)
- **LOLBIN toolchain abuse**: T1127 (trusted developer utilities), T1059 (command/script), T1218 (signed binary proxy)
- **WMI remote exec**: T1047 (WMI), T1021 (remote services, operationally adjacent)
- **WMI persistence**: T1546.003 (WMI Event Subscription)
- **Kerberoasting**: T1558.003 (Kerberoasting)
- **DLL sideload**: T1574.001 (DLL Search Order Hijacking)
- **Registry persistence**: T1547.001 (Run keys), T1546.012 (IFEO), T1546.015 (COM hijack), T1547.009 (LSA/SSP), plus WBEM/WMI artifacts

---

## What this proves (for hiring)
This Sigma layer is not “checkbox Sigma”.
It is an **engineering abstraction** of multi-stage hunt logic with:
- stage separation
- correlation intent
- attacker vs victim perspective
- substrate/blind-spot coverage
- explicit operationalization notes

For full production hunts: see the KQL hunt packs in the main repo.
