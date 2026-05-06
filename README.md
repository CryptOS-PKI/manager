# manager

The Fleet Manager for [CryptOS-PKI](https://github.com/CryptOS-PKI) — an Omni-style web control plane for nodes running [`cryptos`](https://github.com/CryptOS-PKI/cryptos).

Talks to nodes via mTLS gRPC, visualizes the chain of trust, pushes issuance profiles, and monitors fleet health. Holds no private keys.

## Stack

- Go API backend
- React (TypeScript) frontend
- Postgres inventory store
- Designed to run on Kubernetes (Deployment + Service + Ingress; Helm chart shipped alongside the image). Single-node `docker compose` is supported for small deployments.

## Status

Pre-alpha. See the org overview for the rollout plan.

## Companion repos

- [`cryptos`](https://github.com/CryptOS-PKI/cryptos) — the OS / engine.
- [`api`](https://github.com/CryptOS-PKI/api) — shared `.proto` definitions and generated gRPC code.
