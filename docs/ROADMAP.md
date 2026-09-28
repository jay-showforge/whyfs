# Roadmap

## 1.0: automatic provenance labels (this release)

- Machine-wide, automatic labels with no initialization:
  - Linux x86-64, Linux ARM64, Windows x64, Windows ARM64 and WSL2;
  - native collectors (eBPF, ETW) behind an OS service that starts with the OS and recovers
    from crashes.
- The canonical label covers:
  - creator, process chain, user and inputs;
  - history and file identity;
  - agent session, registered or detected;
  - supplied intent only, never inferred;
  - observed impact;
  - observation integrity.
- People: right-click in Explorer and in Linux file managers, and the local WhyFS window for
  search and labels.
- Agents: the local `whyfs-api/1`.  Power users: the CLI.
- Privacy: local only, per-user visibility, secret redaction, retention and `forget`.

## Later (not committed)

- **macOS.**  A future/community target; not supported in 1.0.  It would need an Endpoint
  Security client with the same scope, identity and label semantics.
- **Linux packaging beyond `.deb`**, e.g. RPM.
- **A CO-RE/libbpf Linux loader** replacing the BCC runtime compile: faster start, smaller
  install.
- **Shell integration in the Windows 11 compact context menu.**  It needs a packaged
  (identity-bearing) extension; today the entries are under *Show more options*.
- **More detected agents**, from install-layout signatures.  Registration works for any agent
  today.
