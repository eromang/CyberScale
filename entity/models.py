"""Entity and Assessment models for CyberScale web playground."""

from django.conf import settings
from django.db import models


class CompetentAuthority(models.Model):
    """NIS2 competent authority (e.g., ILR, CSSF, CCB)."""

    name = models.CharField(max_length=255)
    abbreviation = models.CharField(max_length=20)
    ms = models.CharField(max_length=10)
    sectors = models.JSONField(default=list)
    website = models.URLField(blank=True)
    notification_url = models.URLField(blank=True)
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=50, blank=True)
    receives_notifications = models.BooleanField(default=False)

    class Meta:
        unique_together = ("abbreviation", "ms")
        verbose_name_plural = "competent authorities"

    def __str__(self):
        return f"{self.abbreviation} ({self.ms})"


class CSIRT(models.Model):
    """NIS2 CSIRT (e.g., CIRCL, GOVCERT.LU, CERT.be)."""

    name = models.CharField(max_length=255)
    abbreviation = models.CharField(max_length=20)
    ms = models.CharField(max_length=10)
    website = models.URLField(blank=True)
    notification_url = models.URLField(blank=True)
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=50, blank=True)
    emergency_phone = models.CharField(max_length=50, blank=True)
    sectors = models.JSONField(default=list, help_text='Sectors served (["*"] = all, ["public_administration"] = specific)')
    cer_only = models.BooleanField(default=False, help_text="Also serves CER-designated entities regardless of sector")
    receives_notifications = models.BooleanField(default=False)

    class Meta:
        unique_together = ("abbreviation", "ms")
        verbose_name = "CSIRT"
        verbose_name_plural = "CSIRTs"

    def __str__(self):
        return f"{self.abbreviation} ({self.ms})"


class Entity(models.Model):
    """Entity profile — extends Django User."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="entity"
    )
    organisation_name = models.CharField(max_length=255)
    sector = models.CharField(max_length=100)
    entity_type = models.CharField(max_length=100)
    ms_established = models.CharField(max_length=10, default="LU")
    cer_designated = models.BooleanField(default=False, help_text="Designated as critical entity under CER Directive")
    competent_authority = models.CharField(max_length=100, blank=True)
    misp_instance_url = models.URLField(blank=True)
    misp_api_key = models.CharField(max_length=255, blank=True)
    misp_default_tlp = models.CharField(max_length=20, default="tlp:amber")

    # Art. 27 — Address & contact
    address = models.TextField(blank=True)
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=50, blank=True)

    # Art. 27 — Responsible person (legal/management)
    responsible_person_name = models.CharField(max_length=255, blank=True)
    responsible_person_email = models.EmailField(blank=True)

    # Art. 27 — Technical contact (operational/incident response)
    technical_contact_name = models.CharField(max_length=255, blank=True)
    technical_contact_email = models.EmailField(blank=True)
    technical_contact_phone = models.CharField(max_length=50, blank=True)

    # Art. 27 — IP ranges (validated CIDR, stored as JSON list)
    ip_ranges = models.JSONField(default=list, blank=True)

    # Art. 27 — MS where services are provided
    ms_services = models.JSONField(default=list, blank=True)

    # MISP profile tracking
    misp_profile_event_uuid = models.CharField(max_length=36, blank=True)

    class Meta:
        verbose_name_plural = "entities"

    def __str__(self):
        return f"{self.organisation_name} ({self.sector}/{self.entity_type})"


class EntityType(models.Model):
    """A sector/entity_type registration for an Entity. One Entity can have many."""

    entity = models.ForeignKey(
        "Entity", on_delete=models.CASCADE, related_name="entity_types"
    )
    sector = models.CharField(max_length=100)
    entity_type = models.CharField(max_length=100)
    added_at = models.DateTimeField(auto_now_add=True)
    competent_authority = models.ForeignKey(
        "CompetentAuthority", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="entity_types",
    )
    csirt = models.ForeignKey(
        "CSIRT", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="entity_types",
    )
    ca_auto_assigned = models.BooleanField(default=True)
    csirt_auto_assigned = models.BooleanField(default=True)

    class Meta:
        unique_together = ("entity", "entity_type")
        ordering = ["sector", "entity_type"]

    def __str__(self):
        return f"{self.sector}/{self.entity_type}"

    @property
    def label(self):
        """Human-readable label from reference data."""
        from .forms import _load_entity_type_data
        for et in _load_entity_type_data():
            if et["id"] == self.entity_type:
                return et["label"]
        return self.entity_type.replace("_", " ").title()

    @property
    def sector_label(self):
        return self.sector.replace("_", " ").title()


class Assessment(models.Model):
    """Incident assessment record."""

    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("completed", "Completed"),
        ("submitted", "Submitted"),
    ]

    entity = models.ForeignKey(
        Entity, on_delete=models.CASCADE, related_name="assessments"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")

    # Step 1 — Incident context
    description = models.TextField()
    sector = models.CharField(max_length=100)
    entity_type = models.CharField(max_length=100)
    ms_affected = models.JSONField(default=list, blank=True)

    # Step 2 — Impact assessment
    service_impact = models.CharField(max_length=30, default="none")
    data_impact = models.CharField(max_length=30, default="none")
    safety_impact = models.CharField(max_length=30, default="none")
    financial_impact = models.CharField(max_length=30, default="none")
    affected_persons_count = models.IntegerField(default=0)
    impact_duration_hours = models.IntegerField(default=0)
    suspected_malicious = models.BooleanField(default=False)
    physical_access_breach = models.BooleanField(default=False)

    # Step 3 — Sector-specific (JSON blob)
    sector_specific = models.JSONField(default=dict, blank=True)

    # Multi-entity-type support
    affected_entity_types = models.JSONField(
        default=list, blank=True,
        help_text='List of {"sector": "...", "entity_type": "..."} dicts',
    )
    assessment_results = models.JSONField(
        default=list, blank=True,
        help_text="Per-entity-type assessment results",
    )
    per_type_impacts = models.JSONField(
        default=list, blank=True,
        help_text="Per-entity-type impact data (ms_affected, impacts, sector_specific per type)",
    )

    # Step 4 — Results (populated by assessment engine)
    result_significance = models.BooleanField(null=True, blank=True)
    result_significance_label = models.CharField(max_length=30, blank=True)
    result_model = models.CharField(max_length=50, blank=True)
    result_criteria = models.JSONField(default=list, blank=True)
    result_framework = models.CharField(max_length=50, blank=True)
    result_competent_authority = models.CharField(max_length=100, blank=True)
    result_early_warning = models.JSONField(default=dict, blank=True)
    result_raw = models.JSONField(default=dict, blank=True)

    misp_event_uuid = models.CharField(max_length=36, blank=True)
    pdf_generated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Assessment #{self.pk} — {self.entity.organisation_name} ({self.status})"


class Submission(models.Model):
    """Record of assessment exports/submissions."""

    TARGET_CHOICES = [
        ("pdf_download", "PDF Download"),
        ("misp_json_download", "MISP JSON Download"),
        ("misp_push", "MISP Push"),
        ("misp_profile_push", "MISP Profile Push"),
        ("early_warning", "Early Warning"),
    ]
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("success", "Success"),
        ("failed", "Failed"),
    ]

    assessment = models.ForeignKey(
        Assessment, on_delete=models.CASCADE, related_name="submissions"
    )
    submitted_at = models.DateTimeField(auto_now_add=True)
    target = models.CharField(max_length=30, choices=TARGET_CHOICES)
    misp_event_id = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    def __str__(self):
        return f"Submission {self.target} for Assessment #{self.assessment_id}"
