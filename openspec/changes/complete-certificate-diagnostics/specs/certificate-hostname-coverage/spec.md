# Spec Delta

## Purpose

Defines how SSL Doctor decides whether a certificate covers a requested hostname: subjectAltName-only, wildcard-aware rules that match how modern TLS clients verify names.

## ADDED Requirements

### Requirement: Hostnames are matched against subjectAltName only (audit #23)
Coverage SHALL be decided from SAN `dNSName` entries for DNS names and SAN `iPAddress` entries for IP literals. The common name SHALL be ignored. Comparison SHALL be case-insensitive, SHALL ignore one trailing dot, and SHALL compare internationalised names in their A-label (punycode) form.

#### Scenario: CN-only certificate
- **WHEN** the certificate has CN=shop.example and no SAN
- **THEN** coverage is FAIL, with evidence that the CN is ignored by modern clients

#### Scenario: Case and trailing dot
- **WHEN** the requested name is `SHOP.Example.` and the SAN holds `shop.example`
- **THEN** coverage is PASS

#### Scenario: Internationalised name
- **WHEN** the requested name is `bücher.example` and the SAN holds `xn--bcher-kva.example`
- **THEN** coverage is PASS

#### Scenario: IP literal only matches an IP SAN
- **WHEN** the target is `192.0.2.10` and the certificate has `DNS:192.0.2.10` but no IP SAN
- **THEN** coverage is FAIL

### Requirement: Wildcards cover exactly one left-most label (audit #24)
A SAN `*.<domain>` SHALL match a name with exactly one additional left-most label under `<domain>`. It SHALL NOT match `<domain>` itself or deeper names. Wildcards not forming the entire left-most label, wildcards over a single-label domain, and wildcards over a public suffix SHALL NOT match.

#### Scenario: One label below the wildcard
- **WHEN** the SAN holds `*.shop.example` and the name is `a.shop.example`
- **THEN** coverage is PASS

#### Scenario: Apex is not covered
- **WHEN** the SAN holds only `*.shop.example` and the name is `shop.example`
- **THEN** coverage is FAIL

#### Scenario: Two labels below the wildcard
- **WHEN** the SAN holds `*.shop.example` and the name is `a.b.shop.example`
- **THEN** coverage is FAIL

#### Scenario: Partial-label wildcard
- **WHEN** the SAN holds `w*.shop.example` and the name is `www.shop.example`
- **THEN** coverage is FAIL, and the evidence states that partial wildcards are not accepted

#### Scenario: Wildcard over a public suffix
- **WHEN** the SAN holds `*.co.uk` and the name is `example.co.uk`
- **THEN** coverage is FAIL

### Requirement: The same matcher is used by every coverage check
`tls.hostname`, `cert.hostname`, `srv.cert`, `tls.sni`, endpoint comparison and the domain profile SHALL use one matcher with the rules above. The evidence SHALL list the SAN entries checked and the entry that matched.

#### Scenario: Matching entry is named
- **WHEN** `a.shop.example` is covered by `*.shop.example`
- **THEN** the evidence names `*.shop.example` as the matching entry
