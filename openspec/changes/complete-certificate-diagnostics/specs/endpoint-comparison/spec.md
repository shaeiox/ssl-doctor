# Spec Delta

## ADDED Requirements

### Requirement: Both address families are probed when both resolve (audit #28)
When DNS returns both IPv4 and IPv6 addresses, the endpoint comparison SHALL probe at least one address of each family within the existing probe cap, choosing addresses by family before order. Each endpoint record SHALL carry its family (`ipv4` or `ipv6`).

#### Scenario: Five IPv4 and two IPv6 addresses
- **WHEN** DNS returns five IPv4 and two IPv6 addresses and the probe cap is 4
- **THEN** the probed set contains at least one IPv6 address, and every record states its family

#### Scenario: Single family
- **WHEN** DNS returns only IPv4 addresses
- **THEN** the evidence states that no IPv6 address was published

### Requirement: Family-level differences are reported as such (audit #28)
When every comparable endpoint of one family differs from every comparable endpoint of the other family in certificate identity, hostname coverage or chain status, the finding SHALL name the difference as an IPv4/IPv6 difference. When one family is reachable and the other is not, the finding SHALL name the unreachable family without raising a certificate difference.

#### Scenario: IPv6 serves an old certificate
- **WHEN** both IPv4 endpoints serve certificate A and the IPv6 endpoint serves certificate B
- **THEN** the finding is WARNING "IPv6 endpoints differ from IPv4 endpoints in: certificate identity"

#### Scenario: IPv6 unreachable from this network
- **WHEN** IPv4 negotiates and every IPv6 address is unreachable
- **THEN** the evidence states "IPv6 not reachable from this network", and no certificate inconsistency is raised
