# Example 02 — Nessus Network Scanner Suppression

**Archetype:** Network/Zeek FP from an authorized scanner with static IPs  
**Decision:** `suppress`  
**Rule:** Network Port Scan Detected (Zeek `conn` log)

## Scenario

Authorized Nessus Professional scanners at `10.10.5.20` and `10.10.5.21` run weekly vulnerability scans from an isolated security VLAN. The port-scan detection triggers 2,000+ alerts/week from these hosts — 100% FP.

The suppression is IP-exact. Any port scan from outside the security VLAN (`10.10.5.0/28`) still fires.

## Files

| File | Purpose |
|------|---------|
| `sigma-rule.yml` | Vendored Sigma rule for Zeek-based port scan |
| `ddr.yml` | The Detection Decision Record |
| `sigma-filter.yml` | Exported Sigma Filter |

## Key design notes

- `rule_ref.source: internal` — this is an internal rule (not from SigmaHQ)
- `scope.data_sources: [zeek/conn]` — explicitly scoped to the Zeek conn log pipeline
- The IPs are static DHCP reservations; `review_cadence_days: 180` forces review if scanner infra changes
- A change management ticket (`CHG-4499`) is referenced as evidence — the suppression is change-managed

## Reproducing the filter export

```bash
ddr export-sigma-filter ddr.yml
```
