# Contributing to WhyFS

Thank you for your interest.  Issues are welcome, as are reproducible bug reports (with `whyfs
status --json` and the label or error you saw) and discussion of behaviour and platforms.

## Licensing of the project

WhyFS is **source available under the Business Source License 1.1** ([LICENSE](LICENSE)).  It is
not OSI-approved open source.  Each version becomes available under the Apache License 2.0 on its
Change Date.  Commercial production use requires a commercial license from the Licensor
(licensing@tenzorpipe.org).

## Code contributions

The maintainer has **not yet published contributor terms**, so outside code contributions are
not being merged for now.  The terms will say what rights contributors grant, for example a
Developer Certificate of Origin, a contributor license agreement, or neither.

The reason is that WhyFS is offered under commercial licenses as well as BSL 1.1.  The Licensor
can only offer contributed code under those terms with the contributor's explicit permission.
Nothing in this repository asks contributors to assign or relicense their work, and nothing
should be assumed.

Until contributor terms exist:
- open an issue describing the problem or the change you have in mind;
- small, clearly described patches in an issue are welcome as *suggestions*.  The maintainer may
  implement the change independently.

## Development

- **Tests.**  Linux: `make test` (run as root to include the live eBPF tests).  Windows:
  `python -m unittest discover -s tests` with `PYTHONPATH=src;tests`.
- **Gates.**  They run against an installed package, and each one's usage is in the header of
  its script:
  - `scripts/product_gate.py`
  - `scripts/outage_gate.py`
  - `scripts/run_corpus.py`
  - `scripts/secret_gate.py`
  - `scripts/machine_perf.py`
- **Native validation of all supported platforms.**  `.github/workflows/native-validation.yml`.
  [docs/PLATFORM_VALIDATION.md](docs/PLATFORM_VALIDATION.md) says what each result must show.
- **Security issues.**  See [SECURITY.md](SECURITY.md).  Please do not open a public issue for a
  vulnerability.
