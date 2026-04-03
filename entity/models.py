"""Entity and Assessment models for CyberScale web playground."""

from django.conf import settings
from django.db import models


class Entity(models.Model):
    """Entity profile — extends Django User."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="entity"
    )
    organisation_name = models.CharField(max_length=255)
    sector = models.CharField(max_length=100)
    entity_type = models.CharField(max_length=100)
    ms_established = models.CharField(max_length=10, default="LU")
    competent_authority = models.CharField(max_length=100, blank=True)
    misp_instance_url = models.URLField(blank=True)
    misp_api_key = models.CharField(max_length=255, blank=True)
    misp_default_tlp = models.CharField(max_length=20, default="tlp:amber")

    class Meta:
        verbose_name_plural = "entities"

    def __str__(self):
        return f"{self.organisation_name} ({self.sector}/{self.entity_type})"


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
