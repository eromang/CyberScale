"""Forms for entity registration and incident assessment."""

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from .models import Assessment, Entity

# Load choices from reference JSON
import json
from pathlib import Path

_REF_DIR = Path(__file__).resolve().parent.parent / "data" / "reference"


def _load_entity_type_data() -> list[dict]:
    path = _REF_DIR / "nis2_entity_types.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)["entity_types"]


def _sector_choices() -> list[tuple[str, str]]:
    data = _load_entity_type_data()
    seen = {}
    for et in data:
        sid = et["sector"]
        if sid not in seen:
            seen[sid] = sid.replace("_", " ").title()
    return [("", "— Select sector —")] + sorted(seen.items(), key=lambda x: x[1])


def _entity_type_choices() -> list[tuple[str, str]]:
    data = _load_entity_type_data()
    return [("", "— Select entity type —")] + [
        (et["id"], et["label"]) for et in data
    ]


def _entity_types_by_sector() -> dict[str, list[dict]]:
    """Return {sector: [{id, label}, ...]} for HTMX filtering."""
    data = _load_entity_type_data()
    by_sector: dict[str, list[dict]] = {}
    for et in data:
        by_sector.setdefault(et["sector"], []).append(
            {"id": et["id"], "label": et["label"]}
        )
    return by_sector


# Mapping of sectors that have sector-specific fields (LU thresholds)
SECTORS_WITH_SPECIFIC_FIELDS = {"energy", "transport", "health"}


def entity_type_label(entity_type_id: str) -> str:
    """Get human-readable label for an entity type ID."""
    data = _load_entity_type_data()
    for et in data:
        if et["id"] == entity_type_id:
            return et["label"]
    return entity_type_id.replace("_", " ").title()


MS_CHOICES = [
    ("", "— Select member state —"),
    ("AT", "Austria"), ("BE", "Belgium"), ("BG", "Bulgaria"),
    ("CY", "Cyprus"), ("CZ", "Czechia"), ("DE", "Germany"),
    ("DK", "Denmark"), ("EE", "Estonia"), ("ES", "Spain"),
    ("FI", "Finland"), ("FR", "France"), ("GR", "Greece"),
    ("HR", "Croatia"), ("HU", "Hungary"), ("IE", "Ireland"),
    ("IT", "Italy"), ("LT", "Lithuania"), ("LU", "Luxembourg"),
    ("LV", "Latvia"), ("MT", "Malta"), ("NL", "Netherlands"),
    ("PL", "Poland"), ("PT", "Portugal"), ("RO", "Romania"),
    ("SE", "Sweden"), ("SI", "Slovenia"), ("SK", "Slovakia"),
]

SERVICE_IMPACT_CHOICES = [
    ("none", "None"), ("partial", "Partial degradation"),
    ("degraded", "Degraded"), ("unavailable", "Unavailable"),
    ("sustained", "Sustained unavailability"),
]

DATA_IMPACT_CHOICES = [
    ("none", "None"), ("accessed", "Accessed"),
    ("exfiltrated", "Exfiltrated"), ("compromised", "Compromised"),
    ("systemic", "Systemic"),
]

SAFETY_IMPACT_CHOICES = [
    ("none", "None"), ("health_risk", "Health risk"),
    ("health_damage", "Health damage"), ("death", "Death"),
]

FINANCIAL_IMPACT_CHOICES = [
    ("none", "None"), ("minor", "Minor"),
    ("significant", "Significant"), ("severe", "Severe"),
]


class RegistrationForm(UserCreationForm):
    """Combined user + entity registration."""

    organisation_name = forms.CharField(max_length=255)
    sector = forms.ChoiceField(choices=_sector_choices)
    entity_type = forms.ChoiceField(choices=_entity_type_choices)
    ms_established = forms.ChoiceField(choices=MS_CHOICES)

    class Meta:
        model = User
        fields = ("username", "password1", "password2")


class AssessmentStep1Form(forms.Form):
    """Step 1 — Incident context (global fields)."""

    description = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "Describe the incident..."}),
    )
    affected_entity_types = forms.MultipleChoiceField(
        choices=[],
        widget=forms.CheckboxSelectMultiple,
        help_text="Select all entity types affected by this incident.",
    )
    suspected_malicious = forms.BooleanField(required=False, label="Suspected malicious")
    physical_access_breach = forms.BooleanField(required=False, label="Physical access breach (IR only)")

    def __init__(self, *args, entity_types=None, **kwargs):
        super().__init__(*args, **kwargs)
        if entity_types:
            self.fields["affected_entity_types"].choices = [
                (
                    f"{et.sector}:{et.entity_type}",
                    f"{et.sector_label} / {et.label}",
                )
                for et in entity_types
            ]
            if len(entity_types) == 1:
                et = entity_types[0]
                self.fields["affected_entity_types"].initial = [
                    f"{et.sector}:{et.entity_type}"
                ]


class AssessmentStep2Form(forms.Form):
    """Step 2 — Impact assessment."""

    service_impact = forms.ChoiceField(choices=SERVICE_IMPACT_CHOICES)
    data_impact = forms.ChoiceField(choices=DATA_IMPACT_CHOICES)
    safety_impact = forms.ChoiceField(choices=SAFETY_IMPACT_CHOICES)
    financial_impact = forms.ChoiceField(choices=FINANCIAL_IMPACT_CHOICES)
    affected_persons_count = forms.IntegerField(min_value=0, initial=0)
    impact_duration_hours = forms.IntegerField(min_value=0, initial=0, help_text="Duration in hours")
    suspected_malicious = forms.BooleanField(required=False)
    physical_access_breach = forms.BooleanField(required=False, help_text="IR entities only")


class AssessmentStep3Form(forms.Form):
    """Step 3 — Sector-specific fields (LU sectors)."""

    # LU Electricity
    pods_affected = forms.IntegerField(min_value=0, required=False, label="PODs affected")
    voltage_level = forms.ChoiceField(
        choices=[("", "—"), ("lv", "Low voltage"), ("mv", "Medium voltage"), ("hv_ehv", "HV/EHV")],
        required=False,
    )
    scada_unavailable_min = forms.IntegerField(min_value=0, required=False, label="SCADA unavailable (min)")

    # LU Rail
    trains_cancelled_pct = forms.FloatField(min_value=0, max_value=100, required=False, label="Trains cancelled %")
    slots_impacted = forms.IntegerField(min_value=0, required=False, label="Slots impacted")

    # LU Health
    persons_health_impact = forms.IntegerField(min_value=0, required=False, label="Persons with health impact")
    analyses_affected_pct = forms.FloatField(min_value=0, max_value=100, required=False, label="Analyses affected %")

    def get_sector_specific(self) -> dict:
        """Return non-empty sector-specific fields as a dict."""
        result = {}
        for field_name, value in self.cleaned_data.items():
            if value not in (None, "", 0, 0.0):
                result[field_name] = value
        return result


import ipaddress as _ipaddress


class EntityProfileForm(forms.ModelForm):
    """Entity profile editing form with Art. 27 fields."""

    ip_ranges = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "One CIDR per line, e.g.:\n192.168.1.0/24\n10.0.0.0/8"}),
        required=False,
        help_text="IP address ranges in CIDR notation, one per line.",
    )
    ms_services = forms.MultipleChoiceField(
        choices=[(code, label) for code, label in MS_CHOICES if code],
        widget=forms.CheckboxSelectMultiple,
        required=False,
        help_text="Member states where this entity provides services.",
    )

    class Meta:
        model = Entity
        fields = [
            "organisation_name", "address",
            "contact_email", "contact_phone",
            "responsible_person_name", "responsible_person_email",
            "technical_contact_name", "technical_contact_email", "technical_contact_phone",
            "ip_ranges", "ms_services",
            "misp_instance_url", "misp_api_key", "misp_default_tlp",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Pre-populate ip_ranges textarea from JSON list
        if self.instance and self.instance.ip_ranges:
            self.initial["ip_ranges"] = "\n".join(self.instance.ip_ranges)
        # misp_default_tlp has a model default — not required in form
        self.fields["misp_default_tlp"].required = False

    def clean_ip_ranges(self):
        raw = self.cleaned_data.get("ip_ranges", "")
        if not raw.strip():
            return []
        ranges = []
        errors = []
        for i, line in enumerate(raw.strip().split("\n"), 1):
            line = line.strip()
            if not line:
                continue
            try:
                net = _ipaddress.ip_network(line, strict=False)
                ranges.append(str(net))
            except ValueError:
                errors.append(f"Line {i}: '{line}' is not a valid CIDR")
        if errors:
            raise forms.ValidationError(errors)
        return ranges


class EarlyWarningForm(forms.Form):
    """Art. 23(4)(a) early warning submission form."""

    suspected_malicious = forms.BooleanField(required=False, label="Suspected malicious activity")
    cross_border_impact = forms.BooleanField(required=False, label="Cross-border impact")
    initial_assessment = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 6, "placeholder": "Describe the incident: what happened, what systems are affected, current status..."}),
        label="Initial assessment",
    )
    support_requested = forms.BooleanField(required=False, label="Request CSIRT support")
    support_description = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 3, "placeholder": "Describe the support needed (e.g., forensic analysis, containment assistance)..."}),
        required=False,
        label="Support description",
    )

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("support_requested") and not cleaned.get("support_description", "").strip():
            self.add_error("support_description", "Please describe the support needed.")
        return cleaned
