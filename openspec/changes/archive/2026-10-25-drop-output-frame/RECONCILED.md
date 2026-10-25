# Spec reconciliation for `drop-output-frame` (archived 2026-10-25)

The five terminal-interface changes were written in sequence and later ones
replaced parts of earlier ones. At archive time only the requirements that
describe the current shell were merged into `openspec/specs/terminal-interface`;
this note records what happened to each requirement of this change.

## Merged unchanged
- (none)

## Merged with changes
- There is no output frame -> There is no panel around the transcript: results now carry their own frames (terminal-native-shell); the transcript as a whole has none
- The transcript begins directly under the banner -> same name: the composer follows the transcript; nothing is centred
- Commands are separated by one blank line -> same name: no longer 'centred blocks'

## Not merged (superseded)
- Each command's output is centred as a block - replaced by terminal-native-shell: left-aligned, never centred
- The dashed input and status line are unchanged in role - replaced by the rounded composer
