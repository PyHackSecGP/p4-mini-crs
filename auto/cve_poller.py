"""CVE sources for the P4 auto-pipeline.

Two feeds:
  - CISA KEV catalog — known-exploited vulns (highest signal, flagged)
  - NVD CVE API 2.0 — all recent CVEs (configurable window)

match_targets(cves, repos) is a dumb substring match of repo product name
against the CVE's vendor+product field. Not a replacement for a real
CPE-to-github mapping; good enough for well-known projects (openssl, curl,
libxml2, etc.) and keeps us off the complex CPE-mapping tangent.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "p4-mini-crs/1.0 (+auto-pipeline)"


def fetch_kev() -> list[dict[str, Any]]:
    """CISA Known Exploited Vulnerabilities. Returns list of normalized dicts."""
    resp = requests.get(KEV_URL, headers={"User-Agent": UA}, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    out = []
    for v in data.get("vulnerabilities", []):
        out.append({
            "cve_id": v.get("cveID", ""),
            "vendor": (v.get("vendorProject") or "").lower(),
            "product": (v.get("product") or "").lower(),
            "name": v.get("vulnerabilityName", ""),
            "added": v.get("dateAdded", ""),
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "source": "KEV",
            "severity_hint": "CRITICAL",  # KEV = actively exploited
        })
    return out


def fetch_nvd_recent(days: int = 7) -> list[dict[str, Any]]:
    """NVD CVEs published in the last N days. Capped at 2000 (API default)."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    }
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"User-Agent": UA}
    if api_key:
        headers["apiKey"] = api_key
    resp = requests.get(NVD_URL, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        # pull vendor/product from CPE configurations
        vendors, products = set(), set()
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    parts = cpe.get("criteria", "").split(":")
                    if len(parts) >= 5:
                        vendors.add(parts[3].lower())
                        products.add(parts[4].lower())
        metrics = cve.get("metrics", {})
        base_score = None
        severity_hint = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0].get("cvssData", {})
                base_score = m.get("baseScore")
                severity_hint = m.get("baseSeverity", "").upper() or "UNKNOWN"
                break
        out.append({
            "cve_id": cve_id,
            "vendor": "|".join(sorted(vendors)),
            "product": "|".join(sorted(products)),
            "name": next(
                (d.get("value", "") for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"), ""
            )[:200],
            "added": cve.get("published", ""),
            "base_score": base_score,
            "source": "NVD",
            "severity_hint": severity_hint,
        })
    return out


def _repo_product(repo: str) -> str:
    """`owner/repo` → `repo` lowercased. Our only mapping heuristic."""
    return repo.split("/")[-1].lower()


def match_targets(cves: list[dict], github_repos: list[dict]) -> list[dict]:
    """Return list of (repo_entry, cve) tuples for matched pairs.

    Match rule: repo product name appears as substring in CVE vendor OR product
    field. This is coarse but avoids the CPE-mapping rabbit hole. False
    positives are acceptable here because the pipeline re-fuzzes real crashes;
    the CVE match is just a trigger.
    """
    matches = []
    for repo in github_repos:
        if not repo.get("enabled", True):
            continue
        product = _repo_product(repo["repo"])
        if len(product) < 4:  # skip too-generic (e.g. "foo")
            continue
        for cve in cves:
            haystack = f"{cve['vendor']} {cve['product']}"
            if product in haystack:
                matches.append({"repo": repo, "cve": cve})
    return matches


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "kev":
        kev = fetch_kev()
        print(f"KEV entries: {len(kev)}")
        for v in kev[:5]:
            print(f"  {v['cve_id']} {v['vendor']}/{v['product']} — {v['name'][:60]}")
    elif len(sys.argv) > 1 and sys.argv[1] == "nvd":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 7
        nvd = fetch_nvd_recent(days)
        print(f"NVD recent ({days}d): {len(nvd)}")
        for v in nvd[:5]:
            print(f"  {v['cve_id']} ({v['severity_hint']}) {v['vendor']}/{v['product']}")
    else:
        print("usage: cve_poller.py {kev|nvd [days]}")
