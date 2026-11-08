# ONIOPS — Offensive Neural Intelligence

**An open-source, provider-agnostic, autonomous red-team framework.**

ONIOPS drives a Kali toolchain over SSH, reasons with the LLM(s) of your choice
(local or cloud), and runs scope-locked offensive assessments against networks
you are authorized to test. It is the red-team counterpart to a blue-team SOC:
recon, service enumeration, exploit intel, and validated findings — orchestrated
by an AI operator you fully control.

> **Authorized use only.** ONIOPS performs active, intrusive security testing.
> Run it only against systems you own or have explicit written permission to
> test. See [`NOTICE`](NOTICE).

---

## Why ONIOPS

- **Any LLM.** Ollama (local, free), Anthropic Claude, Google Gemini, OpenAI,
  Azure OpenAI, or any OpenAI-compatible endpoint (vLLM, LM Studio, OpenRouter).
  Mix providers per role — e.g. Claude plans, local Ollama summarizes.
- **Portable.** No hardcoded network. You set your scope in `config.yaml`; ONIOPS
  auto-detects your subnet and discovers targets. Runs on Linux, Windows,
  Docker, and Proxmox LXC.
- **Safe by design.** Explicit Rules-of-Engagement scope (allow-list + exclude),
  non-destructive by default, destructive-command guard, full audit log.
- **Pluggable.** Tools, providers, and integrations are drop-in modules.

## Quick start (Docker)

```bash
git clone https://github.com/oniops/oniops.git && cd oniops
cp config.example.yaml config.yaml   # edit: scope + Kali host
cp .env.example .env                 # add any cloud API keys you use
cp /path/to/kali_key secrets/kali_id_rsa
docker compose up -d
# UI on http://localhost:8501
```

Other install paths (Proxmox LXC, Windows, bare Linux, and more) are in
[`docs/INSTALL.md`](docs/INSTALL.md).

## Configuration

Everything environment-specific lives in `config.yaml` (layout) and `.env`
(secrets). Nothing is committed. See [`config.example.yaml`](config.example.yaml).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
