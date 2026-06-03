# 🛰️ manager

The Fleet Manager backend for [CryptOS-PKI](https://github.com/CryptOS-PKI). Optional control plane that talks to many CryptOS CA nodes over mTLS gRPC and serves the [`web`](https://github.com/CryptOS-PKI/web) frontend at the same TLS listener.

## ✨ What it does

- 🌳 **Cross-node visibility.** Walks every linked node's declared `role`, `parent`, and `pair` to render a multi-Root fleet topology. Each Root is sovereign; the FM never crosses Root trust boundaries on its own.
- 📚 **Inventory.** Tracks issued certificates, revocation status, and audit deltas across the fleet. Persists to Postgres (cross-node inventory only — per-node state stays on each node's embedded etcd).
- 📜 **Declarative pushes.** When linked, an FM operator can push `MachineConfig` updates to nodes; nodes verify signatures and apply on next reboot.
- 🚫 **Never an issuance authority.** The FM's peer cert lacks `keyCertSign` and `cRLSign`. The FM cannot sign certificates, even if compromised. Each Root retains full control.

## 🔗 Linking model

A node is linked to the FM via **mutual consent**: the operator declares the FM's URL + trust anchor in the node's machine config and reboots; the node calls the FM's `EnrollNode` with a TPM EK attestation; the FM operator approves in the UI; the FM issues the node a 90-day peer cert (EKU `clientAuth` only). Either side can revoke or unlink.

Once linked, the node's embedded operator surface becomes read-only and FM owns day-to-day operations. Unlinking is a config change + reboot. A node that has never been linked is managed via [`cryptosctl`](https://github.com/CryptOS-PKI/cryptos) only — no web UI in that case (by design — there's no web frontend on the CA image).

## 🧱 Stack

- Go backend, served behind mTLS TLS 1.3.
- Postgres for cross-node inventory.
- Serves the [`web`](https://github.com/CryptOS-PKI/web) bundle (pinned version, embedded via `embed.FS`) on the same listener as the FM gRPC API.
- Designed to run on Kubernetes (Deployment + Service + Ingress, Helm chart shipped alongside the container image). Single-node Docker / `docker compose` is supported for small deployments; K8s is the primary target.

## 🚦 Status

**Pre-alpha.** Backend implementation begins in Phase 2; this repo is currently a placeholder.

## 🧭 Companion repos

- 📡 [`api`](https://github.com/CryptOS-PKI/api) — shared `.proto` definitions and generated gRPC stubs.
- 🧠 [`cryptos`](https://github.com/CryptOS-PKI/cryptos) — the OS / engine that runs the CAs this FM manages.
- 🎨 [`web`](https://github.com/CryptOS-PKI/web) — the FM's web frontend (served by this repo).

## 📄 License

[Apache License 2.0](LICENSE). Copyright 2026 Shane.
