import argparse
from ipaddress import IPv4Address, IPv4Network
import json
from pathlib import Path


def subtract(rect, blocker):
    a, b, c, d = rect
    x, y, p, q = blocker
    left, right = max(a, x), min(b, y)
    low, high = max(c, p), min(d, q)
    if left > right or low > high:
        return [rect]
    pieces = [(a, left-1, c, d), (right+1, b, c, d),
              (left, right, c, low-1), (left, right, high+1, d)]
    return [r for r in pieces if r[0] <= r[1] and r[2] <= r[3]]


def analyze(policy):
    prior, names, report = [], set(), []
    for rule in policy:
        name, proto, action = (rule[k] for k in ("name", "protocol", "action"))
        if not name or name in names or proto not in ("tcp", "udp") or action not in ("allow", "deny"):
            raise ValueError("invalid name, protocol or action")
        names.add(name)
        network = IPv4Network(rule["source"])
        low, high = rule["ports"]
        if type(low) is not int or type(high) is not int or not 0 <= low <= high <= 65535:
            raise ValueError("invalid port range")
        rect = (int(network.network_address), int(network.broadcast_address), low, high)
        remaining, blockers = [rect], []
        for earlier, protocol, decision, area in prior:
            if protocol != proto:
                continue
            new = [piece for region in remaining for piece in subtract(region, area)]
            if new != remaining:
                blockers.append({"name": earlier, "action": decision})
            remaining = new
            if not remaining:
                break
        status = "shadowed" if not remaining else "partial" if blockers else "reachable"
        witness = None
        if remaining:
            src, _, port, _ = remaining[0]
            witness = dict(source=str(IPv4Address(src)), protocol=proto, port=port)
        report.append(dict(name=name, status=status, blockers=blockers, witness=witness))
        prior.append((name, proto, action, rect))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Explain first-match policy reachability")
    parser.add_argument("policy", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(analyze(json.loads(args.policy.read_text(encoding="utf-8"))), indent=2))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"Invalid policy: {exc}\n")
