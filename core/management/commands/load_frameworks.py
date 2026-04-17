"""
Load compliance framework fixtures from YAML files.

Usage:
  python manage.py load_frameworks fixtures/*.yaml
  python manage.py load_frameworks fixtures/cis-k8s-1.23.yaml

YAML format:
  framework:
    id: cis-k8s-1.23
    name: "CIS Kubernetes Benchmark"
    version: "1.23"
    description: "..."
  controls:
    - id: "1.2.1"
      section: "1.2 API Server"
      title: "Ensure anonymous auth is disabled"
      severity: CRITICAL
      check_type: automated
      check_ids: ["AVD-KCV-0001"]
      kyverno_policies: []
      remediation: "Set --anonymous-auth=false"

See: docs/architecture.md § Framework Fixtures
"""
import yaml
from django.core.management.base import BaseCommand, CommandError

from core.constants import TRIVY_SEVERITY_MAP
from core.models.compliance import CheckType, Control, Framework


class Command(BaseCommand):
    help = "Load compliance framework fixtures from YAML files"

    def add_arguments(self, parser):
        parser.add_argument(
            "files",
            nargs="+",
            type=str,
            help="Path(s) to YAML fixture files",
        )

    def handle(self, *args, **options):
        total_frameworks = 0
        total_controls = 0

        for filepath in options["files"]:
            try:
                with open(filepath) as f:
                    data = yaml.safe_load(f)
            except FileNotFoundError:
                raise CommandError(f"File not found: {filepath}")
            except yaml.YAMLError as e:
                raise CommandError(f"Invalid YAML in {filepath}: {e}")

            fw_data = data.get("framework", {})
            if not fw_data.get("id"):
                raise CommandError(f"Missing framework.id in {filepath}")

            # Upsert framework
            framework, created = Framework.objects.update_or_create(
                slug=fw_data["id"],
                defaults={
                    "name": fw_data.get("name", fw_data["id"]),
                    "version": fw_data.get("version", ""),
                    "description": fw_data.get("description", ""),
                    "source": fw_data.get("source", "custom"),
                },
            )
            action = "Created" if created else "Updated"

            # Upsert controls
            controls_data = data.get("controls", [])
            controls_loaded = 0
            for cd in controls_data:
                severity = TRIVY_SEVERITY_MAP.get(
                    cd.get("severity", "MEDIUM").upper(), "Medium"
                )
                check_ids = cd.get("check_ids", [])
                check_type = cd.get("check_type", "automated")
                if check_type not in ("automated", "manual"):
                    check_type = "automated" if check_ids else "manual"

                Control.objects.update_or_create(
                    framework=framework,
                    control_id=cd["id"],
                    defaults={
                        "title": cd.get("title", ""),
                        "severity": severity,
                        "section": cd.get("section", ""),
                        "description": cd.get("description", ""),
                        "remediation": cd.get("remediation", ""),
                        "check_type": check_type,
                        "check_ids": check_ids,
                        "kyverno_policies": cd.get("kyverno_policies", []),
                    },
                )
                controls_loaded += 1

            # Update total_controls
            framework.total_controls = framework.controls.count()
            framework.save(update_fields=["total_controls"])

            self.stdout.write(
                self.style.SUCCESS(
                    f"  {action} {framework.slug}: {controls_loaded} controls"
                )
            )
            total_frameworks += 1
            total_controls += controls_loaded

        self.stdout.write(
            self.style.SUCCESS(
                f"\nLoaded {total_frameworks} frameworks, "
                f"{total_controls} controls total"
            )
        )
