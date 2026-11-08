# Firewall Shadow Map

Find unreachable rules in an ordered IPv4 firewall policy. The analyzer can prove that several earlier rules jointly cover a later rule and give a concrete packet for a partially reachable rule.

## Reproduce the case

Requires Python 3.11+. All examples use synthetic data and run locally with the standard library. Run from the repository root.

```sh
python shadow.py examples/edge-policy.json
```

Two /25 denies jointly shadow the /24 maintenance exception on port 22. The web rule is partially reachable: 192.0.2.0 on port 81 reaches it, while a packet from the same address on port 80 hits the earlier rule.

## Design and limits

A rule describes a source CIDR, one protocol (TCP or UDP), an inclusive destination port range and an action. Each is an address × port rectangle. The analyzer subtracts earlier matching rectangles in order, attributing coverage to the first effective blocker. It emits one surviving point as a reachability witness. This offline model assumes first-match policy and a single destination zone. It does not model stateful return traffic, NAT, interfaces or vendor policy syntax. Fragmentation can grow on large overlapping policies.

## Verification

```sh
python -m unittest discover -s tests -v
```

Tests compare rectangle subtraction to exhaustive enumeration on a small domain, verify cumulative coverage, and check protocol separation and first-match attribution.
