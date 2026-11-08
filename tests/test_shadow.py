import json
from pathlib import Path
import unittest
from shadow import subtract, analyze


def points(rect):
    a, b, c, d = rect
    return {(x,y) for x in range(a,b+1) for y in range(c,d+1)}


class PolicyTests(unittest.TestCase):
    def test_rectangle_difference(self):
        rect = (1,4,1,4)
        for x in range(6):
            for y in range(6):
                blocker = (x,x+1,y,y+1)
                pieces = [points(p) for p in subtract(rect, blocker)]
                seen = set().union(*pieces)
                self.assertEqual(seen, points(rect) - points(blocker))
                self.assertEqual(sum(map(len,pieces)), len(seen))

    def test_first_match_and_joint_coverage(self):
        path = Path(__file__).resolve().parents[1] / "examples/edge-policy.json"
        rules = json.loads(path.read_text())
        rules.append(dict(rules[2], name="udp-exception", protocol="udp"))
        rows = analyze(rules)
        self.assertEqual([b["name"] for b in rows[2]["blockers"]], ["deny-west","deny-east"])
        self.assertIsNone(rows[2]["witness"])
        self.assertEqual(rows[4]["witness"]["port"], 81)
        self.assertEqual(rows[-1]["status"], "reachable")
