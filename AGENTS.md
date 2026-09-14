# Sorta Secret contributor instructions

These instructions apply to the entire repository.

## Product priorities

- Preserve the core purpose: sharing sensitive text more safely than sending plaintext through chat or email.
- Keep security-sensitive behavior explicit and easy to audit.
- Avoid casually changing cryptographic behavior, key handling, expiration semantics, or trust assumptions as part of visual or copy work.
- Prefer a small, dependable product over feature expansion that makes the security model harder to understand.

## Brand and copy

The canonical visual guidelines for Michael's web family live in `snoyberg/snoyman.com`:

[Snoyman web family brand guidelines](https://github.com/snoyberg/snoyman.com/blob/master/docs/brand-guidelines.md)

Before substantial UI, styling, branding, or visual-content work, consult that guide when GitHub access is available.

Sorta Secret should no longer present itself as an FP Complete product. Remove stale FP Complete branding, employer references, logos, links, and visual identity when encountered, while preserving accurate historical attribution where it is genuinely relevant in source history or licensing.

The redesigned site should feel like a focused utility within the Snoyman web family: calm light surfaces, navy/ink text, restrained teal accents, clear typography, generous whitespace, accessible contrast, and minimal decorative noise. It may keep a small amount of distinct personality appropriate to a security tool, but should not introduce an unrelated design system.

## Change hygiene

- Keep redesign work separate from cryptographic or protocol changes unless the task explicitly requires both.
- Preserve unrelated user changes.
- Run the repository's existing tests/build checks before handing off implementation work.
- Do not commit secrets, generated private keys, or deployment credentials.
