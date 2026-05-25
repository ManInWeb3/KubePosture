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
            "--cleanup",
            action="store_true",
            help="Remove all test rows created by this command.",
        )

    def handle(self, *args, **options):
        if options["cleanup"]:
            self._cleanup()
            return

        if options["use_existing_purl"]:
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

        n_ioc = SupplyChainIoc.objects.filter(feed_source=TEST_FEED).count()
        SupplyChainIoc.objects.filter(feed_source=TEST_FEED).delete()
        self.stdout.write(f"  removed {n_ioc} SupplyChainIoc row(s) (feed_source={TEST_FEED!r})")

        n_find = Finding.objects.filter(
            source="supply_chain_ioc", vuln_id__startswith="TEST-",
        ).count()
        Finding.objects.filter(
            source="supply_chain_ioc", vuln_id__startswith="TEST-",
        ).delete()
        self.stdout.write(f"  removed {n_find} Finding row(s) (TEST-* vuln_id)")

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
