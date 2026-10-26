"""Record or compare the outcome of every test id in the suite.

    python tests/baseline/record.py            # print "<id>\t<outcome>" lines
    python tests/baseline/record.py --check    # compare with baseline.tsv

The comparison guards the change `complete-certificate-diagnostics`: no test
id may disappear and no new skip may appear unless baseline.tsv is updated
in the same commit with the reason.  Outcomes are ok | skipped | fail | error.

baseline.tsv was recorded on Linux as root (v0.10.1: 708 tests, 24 skipped);
a non-root run executes two more tests, which is not a regression.
"""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
BASELINE = os.path.join(HERE, "baseline.tsv")


class _Recorder(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = {}

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes[test.id()] = "ok"

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes[test.id()] = "skipped"

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes[test.id()] = "fail"

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes[test.id()] = "error"


def run() -> dict:
    # same layout as `python -m unittest discover -s tests` from the repo root
    sys.path[:0] = [TESTS, os.path.dirname(TESTS)]
    suite = unittest.defaultTestLoader.discover(TESTS, top_level_dir=TESTS)
    # some tests print to stdout; keep the recorded lines clean
    real_stdout = sys.stdout
    with open(os.devnull, "w") as sink:
        sys.stdout = sink
        try:
            runner = unittest.TextTestRunner(stream=sink, resultclass=_Recorder)
            result = runner.run(suite)
        finally:
            sys.stdout = real_stdout
    return result.outcomes


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return dict(line.rstrip("\n").split("\t", 1) for line in fh if line.strip())


def main(argv) -> int:
    outcomes = run()
    if "--check" not in argv:
        for test_id in sorted(outcomes):
            print(f"{test_id}\t{outcomes[test_id]}")
        return 0
    base = load(BASELINE)
    missing = sorted(set(base) - set(outcomes))
    # a baseline test that now skips is a regression; a new test that skips
    # (with its reason in the test) is listed for review only
    new_skips = sorted(t for t, o in outcomes.items()
                       if o == "skipped" and base.get(t) not in (None, "skipped"))
    added_skips = sorted(t for t, o in outcomes.items()
                         if o == "skipped" and t not in base)
    broken = sorted(t for t, o in outcomes.items() if o in ("fail", "error"))
    for label, ids in (("removed", missing), ("newly skipped", new_skips),
                       ("failing", broken), ("added, skipped here", added_skips)):
        for test_id in ids:
            print(f"{label}: {test_id}")
    added = len(set(outcomes) - set(base))
    print(f"{len(outcomes)} tests ({added} added), {len(missing)} removed, "
          f"{len(new_skips)} newly skipped, {len(broken)} failing")
    return 1 if (missing or new_skips or broken) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
