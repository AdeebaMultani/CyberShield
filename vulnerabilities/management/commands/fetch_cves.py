from datetime import date
from decimal import Decimal

import requests

from django.core.management.base import BaseCommand, CommandError
from vulnerabilities.models import Vulnerability

class Command(BaseCommand):
    help = "Fetch a CVE record from the NVD API and save it"

    def add_arguments(self, parser):
        parser.add_argument(
            "cve_id",
            nargs="?",
            default="CVE-2024-3094"
        )

    def handle(self, *args, **options):
        cve_id = options["cve_id"].upper()

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cveId": cve_id}

        self.stdout.write(f"Fetching {cve_id} from NVD...")

        try:
            response = requests.get(
                url,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

        except requests.RequestException as error:
            raise CommandError(f"NVD API request failed: {error}")

        records = data.get("vulnerabilities", [])

        if not records:
            raise CommandError(f"No CVE record found for {cve_id}")

        cve = records[0]["cve"]

        description = next(
            (
                item["value"]
                for item in cve.get("descriptions", [])
                if item.get("lang") == "en"
            ),
            "No English description available."
        )

        # Read CVSS metrics, preferring newer versions.
        metrics = cve.get("metrics", {})
        score = None
        severity = "UNKNOWN"

        for metric_name in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            metric_list = metrics.get(metric_name, [])

            if metric_list:
                metric = metric_list[0]
                cvss_data = metric.get("cvssData", {})

                score = cvss_data.get("baseScore")
                severity = (
                    cvss_data.get("baseSeverity")
                    or metric.get("baseSeverity")
                    or "UNKNOWN"
                )
                break

        if severity not in {
            "CRITICAL", "HIGH", "MEDIUM", "LOW"
        }:
            severity = "UNKNOWN"

        published = cve.get("published", "")
        published_date = (
            date.fromisoformat(published[:10])
            if published else None
        )

        # Extract an affected product CPE, when available.
        def find_cpes(item):
            found = []

            if isinstance(item, dict):
                if item.get("vulnerable") is True:
                    criteria = item.get("criteria")
                    if criteria:
                        found.append(criteria)

                for value in item.values():
                    found.extend(find_cpes(value))

            elif isinstance(item, list):
                for value in item:
                    found.extend(find_cpes(value))

            return found

        cpes = find_cpes(cve.get("configurations", []))
        affected_product = cpes[0][:255] if cpes else ""

        Vulnerability.objects.update_or_create(
            cve_id=cve_id,
            defaults={
                "description": description,
                "severity": severity,
                "cvss_score": (
                    Decimal(str(score)) if score is not None else None
                ),
                "affected_product": affected_product,
                "published_date": published_date,
                "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully saved {cve_id} to CyberSheild!"
            )
        )