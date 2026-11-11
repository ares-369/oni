# Security packs

OniOps loads network assessment playbooks from `playbooks/**/*.yaml` and
`playbooks/**/*.yml`. AI probes load from `playbooks/ai_probes/` and its
subdirectories. Pack IDs must be unique in each loader.

Network playbooks can declare pack provenance and runtime requirements:

```yaml
id: api_access_control
version: 1.2.0
pack:
  id: community_web
  author: Example Maintainer
  homepage: https://example.invalid/security-packs
required_tools: [nmap, nuclei]
safety: active # passive | active | intrusive
tags: [web, api, authorization]
steps:
  - name: Service discovery
    cmd: [nmap, -sV, -F, "{target}"]
    timeout: 60
```

Each loaded playbook exposes its source path and SHA-256 content hash. Its
`required_tools` list is merged with the executables actually used in `steps`,
so missing declarations cannot hide runtime requirements. `sqlmap` and `hydra`
steps must declare `safety: intrusive`; intrusive packs are blocked at the
assessment API unless `scope.allow_intrusive_playbooks: true` is explicitly set
in `config.yaml`. Keep that option false unless the engagement authorizes those
actions. Network
playbooks are limited to ONIOPS's supported scanner commands and every step must
contain the `{target}` placeholder. Arbitrary shell, interpreter, or helper
commands are rejected before the playbook can be loaded. AI probe packs use
the same `pack` mapping with `id`, `version`, and optional `author`.
Hashes identify the loaded bytes; they do not authenticate who published a
pack. Review a pack before enabling it, and use a trusted distribution process
when sharing packs across teams.

Pack commands remain argument arrays and are scope-checked before execution.
`required_tools` and `safety` are descriptive metadata today; the operator must
ensure the chosen attack host has those tools and that the selected assessment
matches the engagement's rules of engagement. Each command is still checked by
the scope guard at dispatch time, including full nmap CIDR and address ranges.
