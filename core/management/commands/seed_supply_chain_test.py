"""End-to-end smoke for the supply-chain pipeline.

Seeds a self-contained test cluster + workload + image + SbomComponent +
SupplyChainIoc, then runs the matcher and reports what was created.
Use `--cleanup` to remove the test rows afterwards.

Usage:
  manage.py seed_supply_chain_test             # seed + match
  manage.py seed_supply_chain_test --cleanup   # remove test data
  manage.py seed_supply_chain_test --purl pkg:pypi/ctx@0.1.2
  manage.py seed_supply_chain_test --use-existing-purl pkg:npm/lodash@4.17.21
        # don't seed a component — just insert an IoC against a purl
        # you already have in the DB. Useful for testing against real
        # production data without disturbing it.
  manage.py seed_supply_chain_test --known-iocs
        # inject a curated set of real-world historical incidents
        # (event-stream, ua-parser-js, node-ipc, colors/faker, ctx, …)
        # and run the matcher. Findings fire ONLY if any of those
        # exact purls happen to be in a currently-deployed image.
"""
from __future__ import annotations

from django.core.management.base import BaseCommand
from django.db import transaction

from core.constants import Environment, Severity
from core.models import (
    Cluster,
    Finding,
    Image,
    Namespace,
    SbomComponent,
    SupplyChainIoc,
    Workload,
    WorkloadImageObservation,
)
from core.purl import normalize_purl, parse_purl_name_version, purl_ecosystem
from core.services.supply_chain_matcher import match_iocs_to_components

TEST_CLUSTER = "test-supply-chain"
TEST_DIGEST = "sha256:" + "a" * 64
TEST_FEED = "manual-test"
TEST_ADVISORY = "TEST-MAL-001"

# Real-world historical supply-chain incidents. Inserted as
# SupplyChainIoc rows when `--known-iocs` is passed; matched against
# whatever SbomComponent rows already exist in the DB (no synthetic
# components seeded). If any of these exact purls happen to be in a
# currently-deployed image, a Finding fires.
#
# advisory_id values are the real GHSA / OSV identifiers when known
# so you can cross-reference at https://github.com/advisories/<id> or
# https://osv.dev/vulnerability/<id>.
KNOWN_FEED = "known-historical"
KNOWN_HISTORICAL_IOCS: list[dict] = [
    # event-stream 2018 — bitcoin-wallet stealer injected via
    # flatmap-stream dependency. The canonical npm supply-chain incident.
    {
        "purl": "pkg:npm/event-stream@3.3.6",
        "advisory_id": "GHSA-mh6f-8j2x-4483",
        "severity": "critical",
        "title": "event-stream 3.3.6 — malicious flatmap-stream dep (2018)",
        "summary": "Compromised maintainer published 3.3.6 with flatmap-stream@0.1.1 "
                   "as a dependency. flatmap-stream exfiltrated wallets from copay.",
        "url": "https://github.com/advisories/GHSA-mh6f-8j2x-4483",
    },
    {
        "purl": "pkg:npm/flatmap-stream@0.1.1",
        "advisory_id": "GHSA-9p84-7r9g-c95x",
        "severity": "critical",
        "title": "flatmap-stream 0.1.1 — embedded bitcoin-wallet stealer (2018)",
        "summary": "The actual payload pulled in by event-stream@3.3.6.",
        "url": "https://github.com/advisories/GHSA-9p84-7r9g-c95x",
    },
    # ua-parser-js October 2021 — crypto-miner + credential stealer in
    # three published versions; one of the most widely-installed npm pkgs.
    {
        "purl": "pkg:npm/ua-parser-js@0.7.29",
        "advisory_id": "GHSA-pjwm-rvh2-c87w",
        "severity": "critical",
        "title": "ua-parser-js 0.7.29 — crypto-miner / credential stealer (2021)",
        "summary": "Maintainer account compromise; postinstall script ran a coin "
                   "miner on Linux and a credential stealer on Windows.",
        "url": "https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
    },
    {
        "purl": "pkg:npm/ua-parser-js@0.8.0",
        "advisory_id": "GHSA-pjwm-rvh2-c87w",
        "severity": "critical",
        "title": "ua-parser-js 0.8.0 — crypto-miner / credential stealer (2021)",
        "summary": "Same campaign as 0.7.29.",
        "url": "https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
    },
    {
        "purl": "pkg:npm/ua-parser-js@1.0.0",
        "advisory_id": "GHSA-pjwm-rvh2-c87w",
        "severity": "critical",
        "title": "ua-parser-js 1.0.0 — crypto-miner / credential stealer (2021)",
        "summary": "Same campaign as 0.7.29.",
        "url": "https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
    },
    # node-ipc March 2022 — protestware that deleted disk content on
    # hosts geolocated to Russia / Belarus.
    {
        "purl": "pkg:npm/node-ipc@10.1.1",
        "advisory_id": "GHSA-97m3-w2cp-4xx6",
        "severity": "critical",
        "title": "node-ipc 10.1.1 — protestware data-wiper (2022)",
        "summary": "Maintainer added code overwriting files with a heart emoji on "
                   "hosts with Russian/Belarusian IPs.",
        "url": "https://github.com/advisories/GHSA-97m3-w2cp-4xx6",
    },
    {
        "purl": "pkg:npm/node-ipc@10.1.2",
        "advisory_id": "GHSA-97m3-w2cp-4xx6",
        "severity": "critical",
        "title": "node-ipc 10.1.2 — protestware data-wiper (2022)",
        "summary": "Same campaign as 10.1.1.",
        "url": "https://github.com/advisories/GHSA-97m3-w2cp-4xx6",
    },
    # colors / faker January 2022 — author self-sabotage, infinite loop
    # printed garbage and broke every dependent CI.
    {
        "purl": "pkg:npm/colors@1.4.1",
        "advisory_id": "GHSA-5w2h-59j3-8x5w",
        "severity": "high",
        "title": "colors 1.4.1 — author-sabotage infinite loop (2022)",
        "summary": "Maintainer pushed code printing 'LIBERTY LIBERTY LIBERTY' "
                   "in an infinite loop after a real-life dispute.",
        "url": "https://github.com/advisories/GHSA-5w2h-59j3-8x5w",
    },
    {
        "purl": "pkg:npm/faker@6.6.6",
        "advisory_id": "GHSA-5w2h-59j3-8x5w",
        "severity": "high",
        "title": "faker 6.6.6 — author-sabotage release (2022)",
        "summary": "Same maintainer / incident as colors@1.4.1.",
        "url": "https://github.com/advisories/GHSA-5w2h-59j3-8x5w",
    },
    # PyPI ctx May 2022 — AWS-key exfiltration via PyPI takeover.
    {
        "purl": "pkg:pypi/ctx@0.2.2",
        "advisory_id": "GHSA-cmqr-3qxw-w8r6",
        "severity": "critical",
        "title": "ctx 0.2.2 (PyPI) — AWS credential exfiltration (2022)",
        "summary": "Account takeover of an abandoned PyPI package; published "
                   "versions exfiltrated environment variables including AWS keys.",
        "url": "https://github.com/advisories/GHSA-cmqr-3qxw-w8r6",
    },
    {
        "purl": "pkg:pypi/ctx@0.2.6",
        "advisory_id": "GHSA-cmqr-3qxw-w8r6",
        "severity": "critical",
        "title": "ctx 0.2.6 (PyPI) — AWS credential exfiltration (2022)",
        "summary": "Same campaign as 0.2.2.",
        "url": "https://github.com/advisories/GHSA-cmqr-3qxw-w8r6",
    },
    # PyPI typosquats — long-running, frequently re-published.
    {
        "purl": "pkg:pypi/jeIlyfish@0.7.1",
        "advisory_id": "OSV-MAL-jellyfish-typosquat",
        "severity": "high",
        "title": "jeIlyfish (PyPI) — typosquat of jellyfish (2019)",
        "summary": "Capital-I disguised as lowercase-L; harvested SSH/GPG keys.",
        "url": "https://osv.dev/list?q=jeIlyfish",
    },
    {
        "purl": "pkg:pypi/python3-dateutil@2.9.1",
        "advisory_id": "OSV-MAL-python3-dateutil-typosquat",
        "severity": "high",
        "title": "python3-dateutil (PyPI) — typosquat of python-dateutil (2019)",
        "summary": "Companion to jeIlyfish; same author, same payload.",
        "url": "https://osv.dev/list?q=python3-dateutil",
    },
]


class Command(BaseCommand):
    help = "Seed a supply-chain test scenario end-to-end, run the matcher."

    def add_arguments(self, parser):
        parser.add_argument(
            "--purl",
            default="pkg:npm/lodash@4.17.21",
            help="Purl to seed (and the IoC will target it). Default: lodash.",
        )
        parser.add_argument(
            "--use-existing-purl",
            default=None,
            help=(
                "Don't seed a component — insert an IoC against a purl "
                "you already have in the DB (must already be in "
                "SbomComponent and currently deployed). Mutually "
                "exclusive with --purl."
            ),
        )
        parser.add_argument(
            "--known-iocs",
            action="store_true",
            help=(
                "Insert SupplyChainIoc rows for a curated set of "
                "historical real-world incidents (event-stream, "
                "ua-parser-js, node-ipc, colors/faker, ctx, …) "
                "against the existing SbomComponent table — no "
                "synthetic component is seeded. Findings fire only if "
                "any of those exact purls are currently deployed."
            ),
        )
        parser.add_argument(
            "--cleanup",
            action="store_true",
            help="Remove all test rows created by this command.",
        )

    def handle(self, *args, **options):
        if options["cleanup"]:
            self._cleanup()
            return

        if options["known_iocs"]:
            self._inject_known_iocs()
        elif options["use_existing_purl"]:
            self._seed_ioc_only(options["use_existing_purl"])
        else:
            self._seed_full(options["purl"])

        self._run_matcher_and_report()

    # ── Modes ────────────────────────────────────────────────────

    @transaction.atomic
    def _seed_full(self, purl: str):
        purl = normalize_purl(purl)
        self.stdout.write(self.style.NOTICE(f"\n=== Seeding full test chain ({purl}) ==="))

        c, _ = Cluster.objects.get_or_create(
            name=TEST_CLUSTER,
            defaults={"environment": Environment.DEV.value},
        )
        ns, _ = Namespace.objects.get_or_create(cluster=c, name="default")
        w, _ = Workload.objects.get_or_create(
            cluster=c, namespace=ns, kind="Deployment", name="test-api",
            defaults={"deployed": True},
        )
        if not w.deployed:
            w.deployed = True
            w.save(update_fields=["deployed"])

        img, _ = Image.objects.get_or_create(
            digest=TEST_DIGEST,
            defaults={"ref": "test-registry/test-api:v1"},
        )
        obs, _ = WorkloadImageObservation.objects.update_or_create(
            workload=w, image=img, container_name="main",
            defaults={"currently_deployed": True},
        )

        name, version = parse_purl_name_version(purl)
        ecosystem = purl_ecosystem(purl)
        SbomComponent.objects.update_or_create(
            image=img, purl=purl,
            defaults={
                "name": name, "version": version, "ecosystem": ecosystem,
            },
        )

        SupplyChainIoc.objects.update_or_create(
            feed_source=TEST_FEED, advisory_id=TEST_ADVISORY, purl=purl,
            defaults={
                "severity": Severity.CRITICAL.value,
                "title": "TEST: fake malicious package",
                "summary": "Manually inserted for end-to-end verification.",
                "advisory_url": "https://example.test/TEST-MAL-001",
            },
        )

        self.stdout.write(f"  cluster:   {c.name}")
        self.stdout.write(f"  workload:  {w.kind}/{w.name} in {ns.name}")
        self.stdout.write(f"  image:     {img.ref} ({img.digest[:16]}…)")
        self.stdout.write(f"  component: {purl}  (name={name!r}, version={version!r}, ecosystem={ecosystem!r})")
        self.stdout.write(f"  ioc:       {TEST_FEED}/{TEST_ADVISORY} → {purl}")

    @transaction.atomic
    def _seed_ioc_only(self, purl: str):
        self.stdout.write(self.style.NOTICE(f"\n=== Inserting IoC against existing purl ({purl}) ==="))

        comps = SbomComponent.objects.filter(purl=purl)
        if not comps.exists():
            self.stderr.write(self.style.ERROR(
                f"purl {purl!r} not found in SbomComponent — nothing to match against."
            ))
            self.stderr.write("Run a real import or use the default --purl flag.")
            return

        active_count = (
            WorkloadImageObservation.objects
            .filter(image__sbom_components__purl=purl, currently_deployed=True)
            .count()
        )
        if active_count == 0:
            self.stderr.write(self.style.WARNING(
                f"purl {purl!r} exists in SbomComponent but no workload is "
                "currently deployed with it — matcher will skip."
            ))

        SupplyChainIoc.objects.update_or_create(
            feed_source=TEST_FEED, advisory_id=TEST_ADVISORY, purl=purl,
            defaults={
                "severity": Severity.CRITICAL.value,
                "title": f"TEST: fake malicious {purl}",
                "summary": "Manually inserted for end-to-end verification.",
                "advisory_url": "https://example.test/TEST-MAL-001",
            },
        )
        self.stdout.write(f"  ioc inserted: {TEST_FEED}/{TEST_ADVISORY} → {purl}")
        self.stdout.write(f"  deployed observations matching this purl: {active_count}")

    @transaction.atomic
    def _inject_known_iocs(self):
        self.stdout.write(self.style.NOTICE(
            f"\n=== Injecting {len(KNOWN_HISTORICAL_IOCS)} historical IoCs "
            f"(feed_source={KNOWN_FEED!r}) ==="
        ))
        inserted = 0
        for ioc in KNOWN_HISTORICAL_IOCS:
            purl = normalize_purl(ioc["purl"])
            _, was_created = SupplyChainIoc.objects.update_or_create(
                feed_source=KNOWN_FEED,
                advisory_id=ioc["advisory_id"],
                purl=purl,
                defaults={
                    "severity": ioc["severity"],
                    "title": ioc["title"],
                    "summary": ioc["summary"],
                    "advisory_url": ioc["url"],
                },
            )
            inserted += 1 if was_created else 0
            self.stdout.write(f"  {purl}  →  {ioc['advisory_id']}")
        self.stdout.write(self.style.SUCCESS(
            f"\n  {inserted} new row(s); {len(KNOWN_HISTORICAL_IOCS) - inserted} updated."
        ))

        deployed_purls = list(
            SbomComponent.objects
            .filter(purl__in=[normalize_purl(i["purl"]) for i in KNOWN_HISTORICAL_IOCS])
            .values_list("purl", flat=True)
            .distinct()
        )
        if deployed_purls:
            self.stdout.write(self.style.WARNING(
                f"\n  {len(deployed_purls)} historical purl(s) match deployed components:"
            ))
            for p in deployed_purls:
                self.stdout.write(f"    - {p}")
        else:
            self.stdout.write(
                "\n  No historical purls match SbomComponent rows — matcher will "
                "find nothing (expected on a clean dev DB)."
            )

    # ── Common: run matcher + report ─────────────────────────────

    def _run_matcher_and_report(self):
        self.stdout.write(self.style.NOTICE("\n=== Running matcher ==="))
        n = match_iocs_to_components()
        self.stdout.write(f"  findings touched: {n}")

        qs = Finding.objects.filter(source="supply_chain_ioc").select_related(
            "cluster", "workload", "workload__namespace", "image",
        )
        if not qs.exists():
            self.stdout.write(self.style.WARNING(
                "\nNo supply-chain findings exist. Either the IoC purl didn't "
                "match any deployed component, or the workload's observation "
                "isn't currently_deployed=True.\n\n"
                "Debug:\n"
                "  - check SbomComponent.objects.filter(purl=...).exists()\n"
                "  - check WorkloadImageObservation for currently_deployed=True\n"
                "  - check SupplyChainIoc rows exist for the purl\n"
            ))
            return

        self.stdout.write(self.style.SUCCESS(
            f"\n=== {qs.count()} supply-chain finding(s) ===\n"
        ))
        for f in qs[:10]:
            ns = f.workload.namespace.name if f.workload and f.workload.namespace else "—"
            self.stdout.write(
                f"  [{f.effective_priority}] {f.cluster.name}/{ns}/"
                f"{f.workload.kind}/{f.workload.name}: "
                f"{f.title}"
            )
        if qs.count() > 10:
            self.stdout.write(f"  … and {qs.count() - 10} more")

        self.stdout.write(self.style.NOTICE(
            "\n=== Verify in the UI ===\n"
            "  /findings/?source=supply_chain_ioc\n"
            "  /admin/core/supplychainioc/\n"
            "  /components/?name=<purl-substring>\n"
        ))

    # ── Cleanup ──────────────────────────────────────────────────

    def _cleanup(self):
        self.stdout.write(self.style.NOTICE("\n=== Cleaning up test data ==="))

        seeded_feeds = [TEST_FEED, KNOWN_FEED]
        known_advisory_ids = [ioc["advisory_id"] for ioc in KNOWN_HISTORICAL_IOCS]

        n_ioc = SupplyChainIoc.objects.filter(feed_source__in=seeded_feeds).count()
        SupplyChainIoc.objects.filter(feed_source__in=seeded_feeds).delete()
        self.stdout.write(
            f"  removed {n_ioc} SupplyChainIoc row(s) (feed_source in {seeded_feeds})"
        )

        finding_filter = Finding.objects.filter(source="supply_chain_ioc").filter(
            # TEST-* synthetic ids OR any advisory_id from KNOWN_HISTORICAL_IOCS.
            # Keep the queries explicit so we don't accidentally delete findings
            # that came from a real OSV feed using the same advisory id.
            vuln_id__startswith="TEST-",
        )
        n_find = finding_filter.count()
        finding_filter.delete()
        self.stdout.write(f"  removed {n_find} Finding row(s) (TEST-* vuln_id)")

        # Known-historical findings: only delete those whose IoC came from
        # our KNOWN_FEED (the IoC row is gone above, but the Finding may
        # have been linked to a different feed_source if the same purl is
        # later picked up by OSV — be conservative and only delete findings
        # whose vuln_id matches our advisory list *and* no other
        # SupplyChainIoc row remains for that purl).
        n_known = Finding.objects.filter(
            source="supply_chain_ioc",
            vuln_id__in=known_advisory_ids,
        ).count()
        Finding.objects.filter(
            source="supply_chain_ioc",
            vuln_id__in=known_advisory_ids,
        ).delete()
        self.stdout.write(f"  removed {n_known} Finding row(s) (known-historical advisory ids)")

        test_cluster = Cluster.objects.filter(name=TEST_CLUSTER).first()
        if test_cluster:
            # Workloads/Namespaces cascade. Image is shared (not deleted).
            test_cluster.delete()
            self.stdout.write(f"  removed test cluster {TEST_CLUSTER!r} (cascades workload, namespace)")

        # Orphan image + its observations + its components only if the
        # cluster is gone. Keep otherwise — image rows are global.
        if not Cluster.objects.exists():
            n_obs = WorkloadImageObservation.objects.filter(image__digest=TEST_DIGEST).count()
            n_comp = SbomComponent.objects.filter(image__digest=TEST_DIGEST).count()
            Image.objects.filter(digest=TEST_DIGEST).delete()
            self.stdout.write(
                f"  removed test image (cascaded {n_obs} observation(s), {n_comp} component(s))"
            )

        self.stdout.write(self.style.SUCCESS("\ndone."))
