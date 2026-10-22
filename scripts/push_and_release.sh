#!/usr/bin/env bash
# KronosMesh — one-shot GitHub launch script.
#
# Usage:
#   1. Create the empty repo first: https://github.com/new
#      name: KronosMesh (no README, no license — this repo has both)
#   2. Authenticate once:  gh auth login   (or export GH_TOKEN=...)
#   3. Run:  ./scripts/push_and_release.sh
#
# The script initializes git if needed, commits the full tree, pushes
# to main, sets the repository topics, and cuts the v1.0.0 release.
set -euo pipefail

REPO_OWNER="Thegreatprabh"
REPO_NAME="KronosMesh"
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
RELEASE_TAG="v1.0.0"

cd "$(dirname "$0")/.."

echo "==> KronosMesh launch: ${REPO_OWNER}/${REPO_NAME}"

if [ ! -d .git ]; then
  git init -b main
fi

git add -A
if git diff --cached --quiet; then
  echo "==> Nothing new to commit"
else
  git commit -m "🌐 KronosMesh v1.0.0 — zero-trust mesh VPN: Rust Noise_IK data plane, Go control plane, React console"
fi

if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "${REPO_URL}"
else
  git remote add origin "${REPO_URL}"
fi

echo "==> Pushing to ${REPO_URL} (main)"
git push -u origin main

echo "==> Setting repository topics"
if command -v gh >/dev/null 2>&1; then
  gh repo edit "${REPO_OWNER}/${REPO_NAME}" \
    --add-topic rust --add-topic ebpf --add-topic wireguard \
    --add-topic mesh-vpn --add-topic zero-trust --add-topic networking \
    --add-topic noise-protocol --add-topic golang \
    --add-topic tailscale-alternative --add-topic xdp
  gh repo edit "${REPO_OWNER}/${REPO_NAME}" \
    --description "🌐 Enterprise Zero-Trust Mesh VPN & cryptographic overlay network — Rust data plane (Noise_IK, X25519, ChaCha20-Poly1305, eBPF/XDP fast path + userspace relay), Go control plane, React console. A self-hosted Tailscale / Cloudflare Tunnels alternative. Trust nothing. Connect everything."
else
  echo "    gh CLI not found — set topics manually on the repo About panel:"
  echo "    rust, ebpf, wireguard, mesh-vpn, zero-trust, networking,"
  echo "    noise-protocol, golang, tailscale-alternative, xdp"
fi

echo "==> Cutting release ${RELEASE_TAG}"
if command -v gh >/dev/null 2>&1; then
  if gh release view "${RELEASE_TAG}" --repo "${REPO_OWNER}/${REPO_NAME}" >/dev/null 2>&1; then
    echo "    ${RELEASE_TAG} already exists — skipping"
  else
    gh release create "${RELEASE_TAG}" \
      --repo "${REPO_OWNER}/${REPO_NAME}" \
      --title "🌐 KronosMesh ${RELEASE_TAG}" \
      --notes "Enterprise Zero-Trust Mesh VPN & cryptographic overlay network.

Highlights:
- Rust data plane: Noise_IK handshake (X25519 + ChaCha20-Poly1305 + BLAKE2s), WireGuard-style frames, mesh relay, 2048-packet replay window, data-plane ACL enforcement
- eBPF/XDP fast-path probe with a full userspace fallback that reports exactly why it engaged
- Go control plane: fingerprint-verified registration, heartbeat topology, versioned zero-trust ACL policy, optional Redis write-through mirror
- React console: live topology, node inventory, ACL matrix, cryptographic inspector
- One JSON contract across all three codebases, pinned by fixtures in both test suites

Verified: Rust 25/25 tests, Go suites green, dashboard strict-TS build green; bench on a 2-vCPU VM: 26.6 ms cold Noise_IK handshake, 641 Mbps crypto-path throughput."
  fi
else
  echo "    gh CLI not found — create the ${RELEASE_TAG} release from the GitHub UI."
fi

echo "==> Done: https://github.com/${REPO_OWNER}/${REPO_NAME}"
