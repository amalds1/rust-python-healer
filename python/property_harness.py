"""Deterministic bounded generative property tests with counterexample shrinking.

Only fixed, trusted builtin properties are evaluated. No package import,
arbitrary expressions, executable project source or user callbacks are allowed.
"""

import argparse
import hashlib
import json
import random


MAX_CASES = 1000
ALLOWED = ("roundtrip_nonnegative", "hex_digest_length", "mutant_double_equals_self")


def validated_config(seed, count, property_name):
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed_must_be_uint32")
    if type(count) is not int or not 1 <= count <= MAX_CASES:
        raise ValueError("invalid_case_budget")
    if property_name not in ALLOWED:
        raise ValueError("property_not_allowlisted")


def fixed_property(name, sample):
    """Strictly selected safe builtins, including one known-killed mutant."""
    if name == "roundtrip_nonnegative":
        return int(str(sample)) == sample and sample >= 0
    if name == "hex_digest_length":
        digest = hashlib.sha256(str(sample).encode("ascii")).hexdigest()
        return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)
    if name == "mutant_double_equals_self":
        return sample + sample == sample
    raise ValueError("property_not_allowlisted")


def shrink_counterexample(name, original):
    """Reduce a nonnegative counterexample to a local minimal integer witness.

    Integer shrinker is deterministic and monotone: every candidate is
    smaller, and it is adopted only while the chosen property still fails.
    """
    if type(original) is not int or not 0 <= original <= 2**31 - 1:
        raise ValueError("invalid_initial_counterexample")
    if fixed_property(name, original):
        raise ValueError("initial_input_is_not_counterexample")
    current = original
    attempts = 0
    while current > 0:
        candidate = current // 2
        if candidate == current:
            break
        attempts += 1
        if not fixed_property(name, candidate):
            current = candidate
        elif candidate + 1 < current and not fixed_property(name, candidate + 1):
            current = candidate + 1
        else:
            # Binary shrinking converges, then verify the immediate predecessor.
            break
    while current > 0 and not fixed_property(name, current - 1):
        current -= 1
        attempts += 1
    return {"minimal_witness": current, "initial_witness": original,
            "shrink_attempts": attempts,
            "witness_is_counterexample": not fixed_property(name, current),
            "immediate_predecessor_passes": current == 0 or fixed_property(name, current - 1)}


def run(seed, count, property_name):
    validated_config(seed, count, property_name)
    rng = random.Random(seed)
    samples = [rng.randrange(0, 2**20) for _ in range(count)]
    # Always include boundary values; random generations are seed-stable.
    samples[:min(count, 3)] = [0, 1, 2][:min(count, 3)]
    failed = next((value for value in samples if not fixed_property(property_name, value)), None)
    shrinking = shrink_counterexample(property_name, failed) if failed is not None else None
    return {"schema_version": 1, "seed": seed, "property": property_name,
            "cases_executed": len(samples),
            "status": "EXPECTED_MUTANT_KILLED" if shrinking and property_name.startswith("mutant_")
                      else "COUNTEREXAMPLE_FOUND" if shrinking else "PASS",
            "first_failing_case": failed,
            "shrinking": shrinking,
            "generator_sha256": hashlib.sha256(json.dumps(samples, separators=(",", ":"))
                                              .encode("ascii")).hexdigest(),
            "user_source_executed": False,
            "property_source": "TRUSTED_FIXED_BUILTINS",
            "external_packages_imported": False,
            "behavioral_equivalence_proven": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--cases", required=True, type=int)
    parser.add_argument("--property", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.seed, args.cases, args.property), sort_keys=True))


if __name__ == "__main__":
    main()
