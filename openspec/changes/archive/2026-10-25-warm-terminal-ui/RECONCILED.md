# Spec reconciliation for `warm-terminal-ui` (archived 2026-10-25)

The five terminal-interface changes were written in sequence and later ones
replaced parts of earlier ones. At archive time only the requirements that
describe the current shell were merged into `openspec/specs/terminal-interface`;
this note records what happened to each requirement of this change.

## Merged unchanged
- Colour is expressed as semantic roles
- Plain mode emits no escape sequences
- Questions to the operator are visually distinct
- Question handling is unchanged
- Indeterminate work uses the signature spinner
- The spinner never corrupts other output
- Determinate progress uses counters
- Text hierarchy is applied consistently
- Help listing keeps every command
- Diagnosis output keeps its content
- Glyphs fall back to ASCII when the terminal cannot show them
- Status never depends on colour
- Windows terminals are prepared or degraded
- report-presentation: all 3 requirements (new main spec)

## Merged with changes
- Colour level is selected from terminal capability -> same name: also lists SSL_DOCTOR_COLOR=never|plain, non-terminal stdout and TERM=dumb, as resolve_color_mode() does
- Colour can be forced for demos and captures -> merged into 'Colour level is selected from terminal capability': the code honours never/plain only; 'always' behaves like automatic detection
- Input stays line-oriented and non-invasive -> The line REPL stays line-oriented and non-invasive: the full-screen shell reads keys in raw mode by design; the rule holds for the line REPL
- Layout uses two-space indent and single-line gaps -> same name: dropped the reference to another change

## Not merged (superseded)
- One frame per command, findings as rows inside it - replaced by terminal-native-shell: 'Each result is framed' (rounded frame)
- Interactive input uses a dashed ASCII frame - replaced by the rounded composer: 'Input is read in a rounded composer'
- The input frame adapts to the terminal width - replaced by merged into the composer requirement (width clause)
- The interactive prompt carries a muted status line - replaced by the session summary lives in the composer's top border
