# Spec reconciliation for `add-fullscreen-tui` (archived 2026-10-25)

The five terminal-interface changes were written in sequence and later ones
replaced parts of earlier ones. At archive time only the requirements that
describe the current shell were merged into `openspec/specs/terminal-interface`;
this note records what happened to each requirement of this change.

## Merged unchanged
- Interactive startup enters a full-screen application mode
- The header adapts to the available height
- Command output is captured into the transcript
- Leaving the application restores the terminal
- The full-screen shell is presentation only

## Merged with changes
- The keyboard drives scrolling, history and editing -> The keyboard drives editing, history and scrolling: Home/End move the cursor; scrolling is PageUp/PageDown (and the wheel) on the transcript - there is no output panel
- Questions and progress appear in the application chrome -> Questions and progress appear in the composer: the status line was replaced by the composer's top border

## Not merged (superseded)
- The application layout is centred and fixed width - replaced by terminal-native-shell: the column is left-aligned, capped at 120, never centred
