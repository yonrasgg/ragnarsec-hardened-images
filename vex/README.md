# VEX exceptions

This directory records reviewed, machine-readable OpenVEX statements for
findings that the scanner reports against a package metadata declaration but
that do not apply to the shipped code. A VEX file is evidence, not a general
scanner waiver.

## Rules

- One file per catalog image: `vex/<image>.openvex.json`. The filename must
  match the catalog image name exactly; a file cannot apply to another image.
- Every statement names one vulnerability and one exact package URL version.
  Wildcards, version ranges, and product-less statements are rejected by
  `tools/image_ci.py`.
- `not_affected` requires a recognized justification and a concrete impact
  statement explaining why the vulnerable code is absent or unreachable.
- Validation records the VEX path and SHA-256 in `validated.json`. Publication
  re-verifies that hash, so a file changed after validation blocks the push.
- Trivy still applies every other scanner and severity rule. A VEX entry must
  not be used to hide a vulnerability that is present in the image.

## Review

Re-check each statement when the affected upstream package changes, when the
scanner database reclassifies the finding, or when the image stops shipping the
vendored component. Delete the statement as soon as the upstream dependency no
longer carries the reported version.
