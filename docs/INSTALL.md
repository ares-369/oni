# Installing OniOps

OniOps has two parts you provide: an **attack host** (a Kali or tooled Linux box it
reaches over SSH) and the **OniOps controller** (this app). The controller is
cross-platform; install it wherever is convenient on your network.

## Supported install targets

| Target | How | Best for |
|---|---|---|
| **Docker / Compose** | `docker compose up -d` | Everyone — one command, works on Linux/Windows/macOS |
| **Proxmox LXC** | `deploy/proxmox-lxc.sh` on a PVE host | Homelabs / self-hosters |
| **Windows (native)** | `deploy/windows-install.ps1` | Windows users (no WSL needed) |
| **Bare Linux** | `bash scripts/install.sh` | Quick local install, one command |
| **Bare Linux + systemd** | `scripts/install.sh` + `deploy/systemd/oniops.service` | Servers, VMs |

### Docker
```bash
cp config.example.yaml config.yaml && cp .env.example .env
# set auth.mode: "local" in config.yaml, and ONIOPS_AUTH_PASSWORD + ONIOPS_SECRET_KEY in .env
docker compose up -d
```
The container listens on `0.0.0.0`, so OniOps refuses to start until a login is configured.
If your Kali host / LLMs are on the same LAN, uncomment `network_mode: host`.

### Proxmox LXC
On the Proxmox host:
```bash
CTID=950 bash deploy/proxmox-lxc.sh
```
Creates an unprivileged Debian 12 container, installs OniOps, enables the service.
Then edit `/opt/oniops/config.yaml` and start it.

### Windows
```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows-install.ps1
.\venv\Scripts\python.exe -m oniops
```
The Kali connection uses pure-Python SSH, so no OpenSSH client or WSL is needed.
For a background service, wrap `python -m oniops` with NSSM.

### pip / pipx (any OS with Python 3.10+)
```bash
pipx install oniops            # or: python -m venv v && v/bin/pip install oniops
oniops init                    # ~/.oniops/config.yaml, .env (random ONIOPS_SECRET_KEY), data/
oniops                         # web UI on http://127.0.0.1:8501
```
Set `ONIOPS_HOME` to keep config and data somewhere other than `~/.oniops`. Optional extras:
`pip install 'oniops[all]'` (cloud LLM SDKs + OIDC), `[browser]`, `[cloud]`.

### Bare Linux
```bash
git clone https://github.com/ares-369/oniops.git oniops && cd oniops
bash scripts/install.sh        # venv, deps, config.yaml, .env, ONIOPS_SECRET_KEY; safe to re-run
venv/bin/python -m oniops
```

### Bare Linux + systemd
The unit expects the install in `/opt/oniops` and runs as user `oniops`. The full, step-by-step
version (create the user, clone to `/opt/oniops`, `scripts/install.sh`, `chown`, enable the unit,
check `/healthz`) is in the README under "Option D".

## Where else OniOps can run

OniOps is a lightweight Flask/waitress controller, so it fits almost anywhere that
runs Python 3.10+ and can reach your Kali host and model endpoint:

- **On the Kali box itself** — controller + tools co-located, no SSH hop. The
  simplest setup for a single-box pentester (point `kali.host` at `127.0.0.1`).
- **WSL2 on Windows** — run the Linux stack cleanly under Windows.
- **Raspberry Pi / ARM SBC** — a low-power always-on controller; offload the LLM
  to a remote Ollama or a cloud provider.
- **Cloud VM** (AWS/Azure/GCP/DigitalOcean/Hetzner) — a hosted red-team console;
  keep the Kali host on the same VPC/subnet.
- **Kubernetes / Helm** — for teams wanting multi-user, scalable deployment.
- **Unraid / Portainer / TrueNAS** — via the Docker image, for NAS/homelab users.
- **Air-gapped / offline labs** — Ollama-only, no cloud keys, local exploit intel.

## After install (any target)
1. Edit `config.yaml`: set `scope.allowed_cidrs` to the network(s) you may test,
   and `kali.host` to your attack box.
2. Put the Kali SSH **private** key in `secrets/` and point `config.yaml` at it.
3. Add cloud API keys to `.env` only for providers you use (Ollama needs none).
4. Open the UI on port `8501`. It listens on `127.0.0.1` by default; to reach it
   from other machines set `oniops.bind_host: "0.0.0.0"` and enable a login
   (`auth.mode`). OniOps refuses to start on a network address without a login,
   and refuses `auth.mode: proxy` without `auth.proxy_trusted_ips`.
