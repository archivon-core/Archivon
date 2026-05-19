# Archivon Core

Archivon Core is a pre-production open-source prototype for access-gated archival storage.

It is built around a simple security idea: logging in should not automatically expose protected archive contents. A client can see only the folders granted to them, and content access is opened through a time-limited session after successful Proof-of-Work verification.

The current core includes:

- Go backend API;
- PostgreSQL schema migrations;
- React/Vite admin and client UI;
- folder-bound Proof-of-Work access policies;
- KMS-sealed policy integrity;
- Stratum-compatible compute verification;
- safe Stratum debugger utility for local protocol checks;
- one active TTL access session per tenant;
- session-gated browser downloads;
- read-only WebDAV access for active sessions;
- audit events for administrative and access operations;
- Docker Compose and nginx deployment templates.

## Security Model

Archivon Core is an access-gated storage prototype, not end-to-end encryption software.

Archive files are stored as server-side objects and are protected by authorization, Proof-of-Work, time-limited access sessions, WebDAV credentials, audit controls, and deployment hardening.

The current KMS role is policy sealing and technical secret protection. Folder Proof-of-Work policies are sealed so they cannot be silently weakened after folder creation.

## Why This Exists

Archivon explores a practical access model for sensitive archives where account login, content visibility, and file access are deliberately separated. The goal is to combine ordinary administrative control with an additional proof layer before protected files become readable.

This project is focused on:

- access sessions that expire automatically;
- folder-level Proof-of-Work policies;
- visible auditability of access decisions;
- compute-backed proof collection through a Stratum-compatible gateway;
- a clean operator/client split in the UI.

## Repository Layout

```text
backend/      Go API, archive access, auth, audit, KMS policy sealing, compute gateway, Stratum debugger
frontend/     React/Vite admin and client interface
frontend/docs/ Public interface examples and frontend reference material
migrations/   PostgreSQL schema migrations
deploy/       Docker Compose and nginx templates
```

## Local Development

Copy the example environment file and adjust values for your local setup:

```sh
cp .env.example .env
```

Start the stack with Docker Compose:

```sh
docker compose -f deploy/docker-compose.yml up --build
```

The public template exposes HTTP, HTTPS, and Stratum ports through environment variables in `.env.example`. Use trusted TLS and production-grade secret handling before any real deployment.

## Current Status

Archivon Core is a pre-production prototype. It is intended for review, research, and community feedback.

Before production use, the project needs:

- independent security review;
- deployment hardening;
- secret rotation procedures;
- compute-gateway threat-model validation;
- operational documentation;
- packaging and upgrade procedures.

## Provenance

Archivon is the result of a long-running research and implementation effort. Some concepts, experiments, notes, and early prototypes predate this public repository.

The work was inspired in part by `ArchiveSafe: Mass-Leakage-Resistant Storage from Proof-of-Work` by Moe Sabry, Reza Samavi, and Douglas Stebila (`arXiv:2009.00086`). Archivon Core is an independent implementation and product direction, but the paper helped frame Proof-of-Work as a useful access barrier for archival information systems rather than only as a cryptocurrency mechanism.

Related prior art also includes [ArchiveSafe](https://github.com/moesabry/ArchiveSafe), the public experimental implementation associated with that research line. Archivon Core is not a fork of ArchiveSafe; it is an independent system with a different architecture, product direction, and operational model. The link is included as research context and acknowledgment of the work that helped shape the broader idea of Proof-of-Work as an access barrier for archival systems.

An earlier public prototype lineage was shared in 2021. Community members reported building software on top of that older core, adapting unused compute devices, and experimenting with compute-backed information-protection workflows. Feedback came from an international audience, including users in Russia, China, and the United States.

That community activity materially influenced the current version. Reports, comments, experiments, and downstream adaptations helped clarify what was useful, what was confusing, and what needed to change before publishing a cleaner core. Some interface ideas in this release were also inspired by community-built projects whose operator workflows were especially clear and practical.

This repository is published from a new public project identity as the current 2026 pre-production core. Earlier Git repositories, notes, and documentation drafts are not part of this public source release. Some of those materials were removed or retired because they reflected older directions and could confuse the scope of the current implementation.

The current implementation has evolved substantially from the earliest idea. This public release should be treated as the canonical open-source snapshot of the cleaned current core, not as a complete archive of every prior experiment.

One long-term goal is to explore useful non-cryptocurrency roles for machines with significant compute capacity. Hardware that was previously used mainly for cryptocurrency mining may still have a second life in access-control, archival, research, and information-protection systems.

This public repository does not rewrite commit history, backdate commits, or imply that the current implementation existed in its present form in earlier years.

## License

Archivon Core is released under the MIT License. See `LICENSE`.
