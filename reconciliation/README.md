# Reconciliation manifests

An active integration PR carries its owner-signed manifest at
`reconciliation/PR-<number>.json` when the protected route verifier requires it.
The verifier reads that exact path from the fetched PR commit as Git object
data; it does not execute files from the candidate checkout or enumerate old
manifests as an authorization list.

Keep the manifest in the active PR until its integration and resulting commit
have been verified. A later reviewed cleanup may remove a completed PR's
manifest from the current tree. Preserve its immutable commit reference and
Git history so that the original bytes and signature remain auditable. Never
rewrite a historical manifest to make it describe a different revision.

Retiring a manifest does not authorize promotion, signing, publication, or a
change of trust policy. It also does not authorize automatic removal or
rewriting of validation receipts, evidence, or receipt chains. Changes to the
current tree require validation for the new revision under the applicable
receipt and promotion contracts.
