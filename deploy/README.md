# Enforced egress deployments

Playwright, Nuclei, ffuf, and `ScopedHttpClient` use `SECURITY_ANALYZER_PROXY`. The browser, Nuclei, and ffuf integrations stay disabled unless both the proxy URL and `SECURITY_ANALYZER_EGRESS_ENFORCED=1` are present. The environment flag is only a deployment assertion; install and verify the network restriction first.

## Docker Compose

The Compose topology keeps the analyzer on an internal-only network and gives only `egress-proxy` an external network. It does not publish proxy port 3128. Start it with:

```sh
docker compose down
docker compose build --no-cache
docker compose up -d
docker compose ps
docker compose logs --tail=100 egress-proxy
```

The analyzer service stays idle so it remains available for the network isolation check and `docker compose exec` commands. Run the CLI inside it with `docker compose exec security-analyzer security-analyzer ...`.

Check that the analyzer cannot open a direct external socket. This command is expected to fail:

```sh
docker compose exec security-analyzer python -c 'import socket; socket.create_connection(("1.1.1.1", 443), timeout=3)'
```

Run an authorized scan through the configured analyzer container only after verifying the network topology and scope policy.

## Dedicated Linux application user

Do not apply the firewall rule to an everyday login account. Create separate service identities and install the project under `/opt/security-analyzer`:

```sh
sudo useradd --system --create-home --shell /usr/sbin/nologin security-analyzer
sudo useradd --system --no-create-home --shell /usr/sbin/nologin security-proxy
sudo python3 -m venv /opt/security-analyzer/.venv
sudo /opt/security-analyzer/.venv/bin/pip install /opt/security-analyzer
sudo install -d -o security-analyzer -g security-analyzer /opt/security-analyzer/output
sudo usermod -aG security-analyzer security-proxy
sudo chgrp -R security-analyzer /opt/security-analyzer
sudo chmod -R g+rX /opt/security-analyzer
```

Install and enable the host guard and proxy service definitions:

```sh
sudo install -m 0750 scripts/enable_host_egress_guard.sh /usr/local/sbin/security-analyzer-egress-guard
sudo install -m 0644 deploy/systemd/security-analyzer-proxy.service /etc/systemd/system/security-analyzer-proxy.service
sudo install -m 0644 deploy/systemd/security-analyzer-egress-guard.service /etc/systemd/system/security-analyzer-egress-guard.service
sudo systemctl daemon-reload
sudo systemctl enable --now security-analyzer-egress-guard
sudo systemctl enable --now security-analyzer-proxy
sudo systemctl status security-analyzer-egress-guard security-analyzer-proxy
sudo nft list table inet security_analyzer_guard
```

The analyzer launcher verifies the per-UID firewall rule and proxy service before setting enforcement variables:

```sh
sudo chmod 0750 scripts/run_security_analyzer_scoped.sh
sudo -u security-analyzer scripts/run_security_analyzer_scoped.sh   /opt/security-analyzer/.venv/bin/security-analyzer --help
```

Replace `--help` with the authorized scan command. The egress-guard rule blocks all outbound packets from the dedicated analyzer UID except loopback; the proxy must run under its separate UID. The firewall rule changes live host network behavior. Review the script and deployment target before enabling it. To remove it, delete only the `inet security_analyzer_guard` nftables table with the appropriate host administrator procedure.
