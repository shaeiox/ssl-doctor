# Installing SSL Doctor (self-hosted, no Docker, no Python)

Verify the bundle first (`VERIFY.md`). Everything below runs offline.

## Linux

```bash
sudo tar -C /opt -xzf ssl-doctor-<version>-linux.tar.gz
sudo mv /opt/ssl-doctor-<version>-linux /opt/ssl-doctor
sudo useradd --system --home /var/lib/ssldoctor-server --create-home ssldoctor

# platform server: embedded PostgreSQL, API, dashboard, scheduler
sudo -u ssldoctor /opt/ssl-doctor/ssldoctor-server/ssldoctor-server init \
     --data /var/lib/ssldoctor-server --org "Your organization" --listen 0.0.0.0:8443 \
     --tls-cert /etc/ssl/ssldoctor.crt --tls-key /etc/ssl/ssldoctor.key
#   -> prints the owner API token once; keep it safe
sudo cp /opt/ssl-doctor/systemd/ssldoctor-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ssldoctor-server

# CLI for engineers
sudo ln -s /opt/ssl-doctor/bin/ssl-doctor /usr/local/bin/ssl-doctor
```

Upgrades: stop the service, extract the new bundle over `/opt/ssl-doctor`, run
`ssldoctor-server upgrade --data /var/lib/ssldoctor-server` as `ssldoctor` (it
takes a backup into `backups/` first), then start the service again.
`ssldoctor-server verify-audit --data …` checks every organization's audit chain.

## Windows

```powershell
Expand-Archive ssl-doctor-<version>-windows.zip C:\ssl-doctor
C:\ssl-doctor\ssldoctor-server\ssldoctor-server.exe init --data C:\ProgramData\ssldoctor-server `
    --org "Your organization" --listen 0.0.0.0:8443
C:\ssl-doctor\ssldoctor-server\ssldoctor-server.exe service install --data C:\ProgramData\ssldoctor-server
C:\ssl-doctor\ssldoctor-server\ssldoctor-server.exe service start
```

## Agents

See `docs/agents.md`. On Windows: `ssl-doctor-agent.exe enroll <url> <token>`,
then `ssl-doctor-agent.exe service install` and `service start`.
