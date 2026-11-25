# WGDashboard size budget — 2026-11-25

Owner-authorized override for `ragnarsec-wgdashboard` from 262,144,000 to 293,601,280 bytes (280 MiB), applied via `budget-overrides.json` so `budgets.json` stays merge-clean across protected branches.

Rationale: the pinned upstream base image `ghcr.io/wgdashboard/wgdashboard@sha256:8c5b550d…` is 275,087,872 bytes uncompressed on linux/arm64, already 13,943,872 bytes above the previous budget before any RagnarSec layer is added. Deleting pip or stale vendor metadata in an upper layer does not reclaim base-layer bytes under the current `archive_layer_bytes` accounting. Reducing the image below the old budget would require replacing the upstream base, which is outside the scope of the release-25 remediation and would change the reviewed application interface.

This adjustment affects the size guard only. Trivy `HIGH,CRITICAL`, structure tests, signature verification and protected promotion rules remain unchanged. Evidence: Jenkins PR-192 build 3 console (`IMAGE_LAYER_BYTES ragnarsec-wgdashboard linux/arm64 275087872`) and the scoped OpenVEX in `vex/ragnarsec-wgdashboard.openvex.json`.
