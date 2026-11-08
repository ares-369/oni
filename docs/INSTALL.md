# Installing ONIOPS

ONIOPS has two parts you provide: an **attack host** (a Kali or tooled Linux box it
reaches over SSH) and the **ONIOPS controller** (this app). The controller is
cross-platform; install it wherever is convenient on your network.

## Supported install targets

| Target | How | Best for |
|---|---|---|
| **Docker / Compose** | `docker compose up -d` | Everyone — one command, works on Linux/Windows/macOS |
| **Proxmox LXC** | `deploy/proxmox-lxc.sh` on a PVE host | Homelabs / self-hosters |
| **Windows (native)** | `deploy/windows-install.ps1` | Windows users (no WSL needed) |
| **Bare Linux + systemd** | venv + `deploy/systemd/oniops.service` | Servers, VMs |
| **pipx** | `pipx install oniops` | Quick local CLI run |

### Docker
```bash
cp config.example.yaml config.yaml && cp .env.example .env
docker compose up -d
```
If your Kali host / LLMs are on the same LAN, uncomment `network_mode: host`.

### Proxmox LXC
On the Proxmox host:
```bash
CTID=950 bash deploy/proxmox-lxc.sh
```
Creates an unprivileged Debian 12 container, installs ONIOPS, enables the service.
Then edit `/opt/oniops/config.yaml` and start it.

### Windows
```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows-install.ps1
.\venv\Scripts\python.exe -m oniops
```
The Kali connection uses pure-Python SSH, so no OpenSSH client or WSL is needed.
For a background service, wrap `python -m oniops` with NSSM.

### Bare Linux + systemd
```bash
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
cp config.example.yaml config.yaml && cp .env.example .env
sudo cp deploy/systemd/oniops.service /etc/systemd/system/
sudo systemctl enable --now oniops
```

## Where else ONIOPS can run

ONIOPS is a lightweight Flask/waitress controller, so it fits almost anywhere that
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
4. Open the UI on port `8501`.
