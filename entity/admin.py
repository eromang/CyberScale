import csv
import os
import uuid as uuid_mod

from django.contrib import admin, messages
from django.http import HttpResponse

MISP_SSL_VERIFY = os.environ.get("MISP_SSL_VERIFY", "").lower() not in ("0", "false", "no", "")

from .models import Assessment, CompetentAuthority, CSIRT, Entity, EntityType, Submission


class EntityTypeInline(admin.TabularInline):
    model = EntityType
    fields = ("sector", "entity_type", "competent_authority", "csirt", "ca_auto_assigned", "added_at")
    readonly_fields = ("added_at",)
    extra = 1


class AssessmentInline(admin.TabularInline):
    model = Assessment
    fields = ("id", "created_at", "status", "result_significance_label", "result_model", "result_framework")
    readonly_fields = ("id", "created_at", "status", "result_significance_label", "result_model", "result_framework")
    extra = 0
    max_num = 0
    show_change_link = True
    ordering = ("-created_at",)

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


def push_profile_to_misp(modeladmin, request, queryset):
    """Push selected entity profiles to MISP."""
    from .misp_profile_export import build_misp_profile_event
    from .misp_push import push_event

    for entity in queryset:
        if not entity.misp_instance_url or not entity.misp_api_key:
            messages.error(request, f"{entity.organisation_name}: MISP URL and API key required.")
            continue

        if not entity.misp_profile_event_uuid:
            entity.misp_profile_event_uuid = str(uuid_mod.uuid4())
            entity.save(update_fields=["misp_profile_event_uuid"])

        event_dict = build_misp_profile_event(entity)

        result = push_event(entity.misp_instance_url, entity.misp_api_key, event_dict, ssl=MISP_SSL_VERIFY)

        if result["success"]:
            latest = entity.assessments.order_by("-created_at").first()
            if latest:
                Submission.objects.create(
                    assessment=latest,
                    target="misp_profile_push",
                    misp_event_id=result["event_id"] or "",
                    status="success",
                )
            messages.success(request, f"{entity.organisation_name}: Profile pushed (ID: {result['event_id']}).")
        else:
            latest = entity.assessments.order_by("-created_at").first()
            if latest:
                Submission.objects.create(
                    assessment=latest,
                    target="misp_profile_push",
                    status="failed",
                )
            messages.error(request, f"{entity.organisation_name}: Push failed — {result['error']}")


push_profile_to_misp.short_description = "Push profile to MISP"


@admin.register(CompetentAuthority)
class CompetentAuthorityAdmin(admin.ModelAdmin):
    list_display = ("abbreviation", "name", "ms", "receives_notifications")
    list_filter = ("ms", "receives_notifications")
    search_fields = ("name", "abbreviation")


@admin.register(CSIRT)
class CSIRTAdmin(admin.ModelAdmin):
    list_display = ("abbreviation", "name", "ms", "receives_notifications", "emergency_phone")
    list_filter = ("ms", "receives_notifications")
    search_fields = ("name", "abbreviation")


@admin.register(EntityType)
class EntityTypeAdmin(admin.ModelAdmin):
    list_display = ("entity", "sector", "entity_type", "competent_authority", "csirt", "ca_auto_assigned", "added_at")
    list_filter = ("sector", "competent_authority", "csirt")
    search_fields = ("entity__organisation_name", "entity_type")
    actions = ["reassign_authority"]

    @admin.action(description="Re-assign authority automatically")
    def reassign_authority(self, request, queryset):
        from .authority import assign_authority
        count = 0
        for et in queryset:
            et.ca_auto_assigned = True
            et.csirt_auto_assigned = True
            et.save(update_fields=["ca_auto_assigned", "csirt_auto_assigned"])
            assign_authority(et)
            count += 1
        messages.success(request, f"Re-assigned authority for {count} entity type(s).")


@admin.register(Entity)
class EntityAdmin(admin.ModelAdmin):
    list_display = ("organisation_name", "ms_established", "contact_email", "responsible_person_name", "competent_authority")
    list_filter = ("ms_established",)
    search_fields = ("organisation_name", "user__username")
    readonly_fields = ("misp_profile_event_uuid",)
    inlines = [EntityTypeInline, AssessmentInline]
    actions = [push_profile_to_misp]
    fieldsets = (
        ("Organisation", {"fields": ("user", "organisation_name", "address", "ms_established", "competent_authority")}),
        ("General Contact", {"fields": ("contact_email", "contact_phone")}),
        ("Responsible Person", {"fields": ("responsible_person_name", "responsible_person_email")}),
        ("Technical Contact", {"fields": ("technical_contact_name", "technical_contact_email", "technical_contact_phone")}),
        ("Service Provision", {"fields": ("ms_services",)}),
        ("IP Ranges", {"fields": ("ip_ranges",)}),
        ("MISP Settings", {"fields": ("misp_instance_url", "misp_api_key", "misp_default_tlp", "misp_profile_event_uuid")}),
    )


def export_assessments_csv(modeladmin, request, queryset):
    """Export selected assessments as CSV."""
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="cyberscale-assessments.csv"'
    writer = csv.writer(response)
    writer.writerow([
        "ID", "Entity", "Sector", "Entity Type", "Status",
        "Significance", "Framework", "Authority", "Model", "Created",
    ])
    for a in queryset.select_related("entity"):
        writer.writerow([
            a.id,
            a.entity.organisation_name,
            a.sector,
            a.entity_type,
            a.status,
            a.result_significance_label,
            a.result_framework,
            a.result_competent_authority,
            a.result_model,
            a.created_at.strftime("%Y-%m-%d %H:%M"),
        ])
    return response


export_assessments_csv.short_description = "Export selected as CSV"


def push_to_misp(modeladmin, request, queryset):
    """Push selected assessments to MISP (admin action)."""
    from .misp_export import build_misp_event_global, build_misp_event
    from .misp_push import push_event

    for assessment in queryset.select_related("entity"):
        entity = assessment.entity

        if assessment.status != "completed":
            messages.error(request, f"Assessment #{assessment.pk}: Only completed assessments can be pushed.")
            continue

        if not entity.misp_instance_url or not entity.misp_api_key:
            messages.error(request, f"Assessment #{assessment.pk}: Entity MISP URL and API key required.")
            continue

        if not entity.misp_profile_event_uuid:
            messages.error(request, f"Assessment #{assessment.pk}: Entity profile must be pushed to MISP before pushing assessments.")
            continue

        if not assessment.misp_event_uuid:
            assessment.misp_event_uuid = str(uuid_mod.uuid4())
            assessment.save(update_fields=["misp_event_uuid"])

        profile_uuid = entity.misp_profile_event_uuid

        if assessment.assessment_results:
            event_dict = build_misp_event_global(assessment, entity, profile_event_uuid=profile_uuid)
        else:
            event_dict = build_misp_event(assessment, entity, profile_event_uuid=profile_uuid)

        result = push_event(entity.misp_instance_url, entity.misp_api_key, event_dict, ssl=MISP_SSL_VERIFY)

        if result["success"]:
            Submission.objects.create(
                assessment=assessment,
                target="misp_push",
                misp_event_id=result["event_id"] or "",
                status="success",
            )
            messages.success(request, f"Assessment #{assessment.pk}: Pushed (ID: {result['event_id']}).")
        else:
            Submission.objects.create(
                assessment=assessment,
                target="misp_push",
                status="failed",
            )
            messages.error(request, f"Assessment #{assessment.pk}: Push failed — {result['error']}")


push_to_misp.short_description = "Push to MISP"


@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = (
        "id", "entity", "status", "result_significance_label",
        "result_framework", "result_competent_authority", "result_model", "created_at",
    )
    list_filter = ("status", "result_significance_label", "result_model", "result_framework", "sector")
    search_fields = ("entity__organisation_name", "description")
    date_hierarchy = "created_at"
    readonly_fields = (
        "result_significance", "result_significance_label", "result_model",
        "result_criteria", "result_framework", "result_competent_authority",
        "result_early_warning", "result_raw", "misp_event_uuid",
    )
    actions = [export_assessments_csv, push_to_misp]


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ("id", "assessment", "get_entity", "target", "status", "submitted_at")
    list_filter = ("target", "status")
    date_hierarchy = "submitted_at"
    raw_id_fields = ("assessment",)

    @admin.display(description="Entity")
    def get_entity(self, obj):
        return obj.assessment.entity.organisation_name
