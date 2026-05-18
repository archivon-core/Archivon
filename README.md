# Archivon Core

Archivon Core is a pre-production research prototype for access-gated archival storage.

This repository is currently a description-only public preview. Source code is intentionally not included yet. The cleaned source release is being prepared separately so that private deployment history, internal notes, local infrastructure details, generated outputs, logs, credentials, and other non-public artifacts are not published by accident.

## Core Idea

Archivon explores a practical access model for sensitive archives where account login, content visibility, and file access are deliberately separated.

The design goal is simple: signing in should not automatically expose protected archive contents. A user may be allowed to see that a protected folder exists, but actual file access is opened only through a time-limited session after an additional Proof-of-Work verification step.

## Intended Public Core

The cleaned source release is expected to include:

- a Go backend API;
- PostgreSQL schema migrations;
- a React/Vite admin and client interface;
- folder-bound Proof-of-Work access policies;
- KMS-sealed policy integrity;
- Stratum-compatible compute verification;
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

Archivon is interested in useful non-cryptocurrency roles for machines with significant compute capacity. Hardware that was previously used mainly for cryptocurrency mining may still have a second life in access-control, archival, research, and information-protection systems.

This project is especially focused on:

- access sessions that expire automatically;
- folder-level Proof-of-Work policies;
- visible auditability of access decisions;
- compute-backed proof collection through a Stratum-compatible gateway;
- a clean operator/client split in the UI.

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

An earlier public prototype lineage was shared in 2021. Community members reported building software on top of that older core, adapting unused compute devices, and experimenting with compute-backed information-protection workflows. Feedback came from an international audience, including users in Russia, China, and the United States.

That community activity materially influenced the current version. Reports, comments, experiments, and downstream adaptations helped clarify what was useful, what was confusing, and what needed to change before publishing a cleaner core. Some interface ideas in the upcoming cleaned source release were also inspired by community-built projects whose operator workflows were especially clear and practical.

This repository is published from a new public project identity as the current 2026 pre-production direction. Earlier Git repositories, notes, and documentation drafts are not part of this public preview. Some of those materials were removed or retired because they reflected older directions and could confuse the scope of the current implementation.

The current implementation has evolved substantially from the earliest idea. This public preview should be treated as the canonical open-source direction for the cleaned current core, not as a complete archive of every prior experiment.

This public repository does not rewrite commit history, backdate commits, or imply that the current implementation existed in its present form in earlier years.

## Publication Plan

This preview publishes the idea first. The cleaned source code is planned for a later public release after final scrubbing, license selection, and repository hygiene checks.

