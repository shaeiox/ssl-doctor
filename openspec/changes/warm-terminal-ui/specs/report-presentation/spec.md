# Spec Delta

## Purpose

Defines the visual treatment of the self-contained HTML report produced by
`/report html` and by the service: it adopts the terminal palette while its
content, structure and findings-contract payload stay unchanged.

## ADDED Requirements

### Requirement: The report uses the shared palette
The report stylesheet SHALL use the same semantic palette as the terminal
output: terracotta `#d77757` as the accent, hot pink `#fd5db1` for machine-
generated identifiers, and `#4eba65` / `#ffc107` / `#ff6b80` / `#888888` for
PASS / WARNING / FAIL / NOT TESTED. Status pills, badges, cause borders and
section rules SHALL draw from those roles only.

#### Scenario: Status colours match the terminal
- **WHEN** a report containing PASS, FAIL, WARNING and NOT TESTED findings is rendered
- **THEN** each badge uses its role colour and the same status word as the terminal output

### Requirement: The report stays self-contained and printable
The stylesheet SHALL remain inline in the single HTML file, with no scripts, no
remote fonts, no external stylesheets and no images. The document SHALL keep a
light background and body and badge contrast of at least 4.5:1, so it remains
readable when printed or attached to a ticket.

#### Scenario: Offline open
- **WHEN** the report file is opened on a machine with no network access
- **THEN** it renders fully styled with no failed external requests

#### Scenario: Printed copy
- **WHEN** the report is printed in monochrome
- **THEN** every status is still identifiable from its text label

### Requirement: Report content and contract are unchanged
The restyle SHALL NOT change the document's sections, their order, the summary
counts, the diagnosis entries, the not-tested badge label, the metadata lines or
any field of the findings-contract payload. Changes SHALL be limited to CSS and
presentational class attributes.

#### Scenario: Payload equality
- **WHEN** the same findings and diagnosis are rendered before and after this change
- **THEN** the JSON payload is identical

#### Scenario: Section order
- **WHEN** a report with local, network and server findings is rendered
- **THEN** the sections appear in the same order with the same headings as before
