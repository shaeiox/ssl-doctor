# Scan agents

Agents run SSL Doctor checks inside your network and report to the control
plane. They open every connection themselves (outbound HTTPS only) and listen
on nothing. There are two roles:

| Role | Install on | Runs |
|---|---|---|
| `client` | a machine on the same network path as the affected users (Windows or Linux) | network checks against the target, and client-machine checks (clock, proxy, Windows stores, chain engine) |
| `server` | the nginx host itself | read-only nginx checks (`nginx -T` or the readable files under `/etc/nginx`), the configured vs presented certificate, TLS log lines. No SSH, and no credentials are given to anyone |

An agent declines jobs of the other role. Jobs name only a kind and a target,
and nothing received from the service is executed.

## 1. Create an enrollment token (owner/admin)

```bash
curl -s -X POST "$SSLDOCTOR_URL/v1/enrollment-tokens" \
  -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "web01-nginx", "role": "server"}'
# -> {"token": "...", "expires_at": "...", "role": "server"}
```

The token is single-use and expires after 24 hours.

## 2a. Linux (systemd)

```bash
python3 -m venv /opt/ssl-doctor && /opt/ssl-doctor/bin/pip install ssl-doctor
sudo useradd --system --home /var/lib/ssl-doctor --create-home ssldoctor
sudo -u ssldoctor /opt/ssl-doctor/bin/ssl-doctor agent enroll "$SSLDOCTOR_URL" "$TOKEN" \
  --state /var/lib/ssl-doctor/agent.json
```

`/etc/systemd/system/ssl-doctor-agent.service`:

```ini
[Unit]
Description=SSL Doctor scan agent
After=network-online.target
Wants=network-online.target

[Service]
User=ssldoctor
ExecStart=/opt/ssl-doctor/bin/ssl-doctor agent run --state /var/lib/ssl-doctor/agent.json
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/ssl-doctor
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now ssl-doctor-agent
journalctl -u ssl-doctor-agent -f
```

For a `server` agent, let the `ssldoctor` account read the nginx
configuration and the certificate files (for example, group membership with
read access). It never needs to read private keys beyond the pairing digest,
and it never needs `sudo`. Checks it can't perform report `NOT TESTED`,
naming the missing permission.

## 2b. Windows (service)

```powershell
py -m venv C:\ssl-doctor; C:\ssl-doctor\Scripts\pip install ssl-doctor
C:\ssl-doctor\Scripts\ssl-doctor agent enroll $env:SSLDOCTOR_URL $TOKEN `
  --state C:\ProgramData\ssl-doctor\agent.json
# run as a service with any service wrapper, e.g. NSSM:
nssm install SSLDoctorAgent C:\ssl-doctor\Scripts\ssl-doctor.exe `
  agent run --state C:\ProgramData\ssl-doctor\agent.json
nssm start SSLDoctorAgent
```

Run the service under the account whose trust stores matter. Use a user
account to see that user's stores, or LocalSystem for machine stores.

## Revoking an agent

```bash
curl -s -X POST "$SSLDOCTOR_URL/v1/agents/$AGENT_ID/revoke" -H "Authorization: Bearer $API_TOKEN"
```

From then on every request from the agent is refused, and results it tries
to upload are discarded. A revoked agent exits with status 2.
