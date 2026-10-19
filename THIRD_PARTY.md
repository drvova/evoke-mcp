# Third-party components

The required Windows operation runtime compiles the original implementations from
**noahware/KernEmul**, pinned at `cf3aedc6cc1755d2fedad77dcd4671bf045f9de8`.
Upstream declares GPL-2.0 in its [README](https://github.com/noahware/kernemul/blob/cf3aedc6cc1755d2fedad77dcd4671bf045f9de8/readme.md).
Credit: noahware and upstream contributors, including the credits in that README.
The source archive retains those notices. `cmake/kernemul/adapter.patch` records
our changes: named-handler registration metadata, image-free bootstrapping,
and local-only symbol lookup. Operation bodies are upstream implementations.

- **Unicorn Engine**, pinned at `7c5db94191defc1e04a4f66f4eb1220903cba837`,
  with KernEmul's four included Unicorn patches — GPL-2.0 and component notices.
  Required, linked into the server core and worker. See the fetched `COPYING`.
- **nlohmann JSON 3.12.0** — MIT, fetched archive retains its license.
- **spdlog 1.15.3** — MIT; includes fmt with its bundled license.
- **Molecular Matters raw_pdb** — BSD-2-Clause; fetched `LICENSE` retained.
- **noahware/pe** — Apache-2.0; fetched `LICENSE` retained.
- **ia32-doc** — upstream README declares MIT; preserve upstream notices.
- **OpenSSL** — system/vcpkg dependency; retain the notices and license for the
  version distributed (OpenSSL 3 is Apache-2.0).
- **cpp-httplib** — MIT; included header retains the upstream notice in
  `driver-mcp/source/httplib/httplib.h`.

Exact source revisions, URLs, and SHA-256 digests for the worker dependencies are
in `cmake/kernemul/dependencies.json`. Binary redistribution must satisfy the
applicable licenses and corresponding-source obligations, including our adapter
patch and build scripts. KernEmul declares GPL-2.0 while its PE dependency and
OpenSSL 3 use Apache-2.0; this upstream license combination requires resolution
before distributing combined binaries. This file does not assign a license to
the repository's own source files.
