# Spec reconciliation for `terminal-native-shell` (archived 2026-10-25)

The five terminal-interface changes were written in sequence and later ones
replaced parts of earlier ones. At archive time only the requirements that
describe the current shell were merged into `openspec/specs/terminal-interface`;
this note records what happened to each requirement of this change.

## Merged unchanged
- The transcript scrolls with the mouse wheel
- Typing `/` offers completions and Tab accepts one
- Each result is framed

## Merged with changes
- The transcript is left-aligned, never centred -> same name: the dashed input rules became the composer; the startup banner is the one centred element

## Not merged (superseded)
- (none)
