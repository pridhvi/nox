#!/usr/bin/env python3
import json
import sys


def main():
    request = json.load(sys.stdin)
    response = {
        "version": request.get("version", "1"),
        "findings": [],
        "new_targets": [],
        "technologies": [],
        "error": None,
    }
    json.dump(response, sys.stdout)


if __name__ == "__main__":
    main()

