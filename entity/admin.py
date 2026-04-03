import csv

from django.contrib import admin
from django.http import HttpResponse

from .models import Assessment, Entity, EntityType, Submission


class EntityTypeInline(admin.TabularInline):
    model = EntityType
    fields = ("sector", "entity_type", "added_at")
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


@admin.register(EntityType)
class EntityTypeAdmin(admin.ModelAdmin):
    list_display = ("entity", "sector", "entity_type", "added_at")
    list_filter = ("sector",)
    search_fields = ("entity__organisation_name", "entity_type")


@admin.register(Entity)
class EntityAdmin(admin.ModelAdmin):
    list_display = ("organisation_name", "ms_established", "competent_authority")
    list_filter = ("ms_established",)
    search_fields = ("organisation_name", "user__username")
    inlines = [EntityTypeInline, AssessmentInline]


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
        "result_early_warning", "result_raw",
    )
    actions = [export_assessments_csv]


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ("id", "assessment", "get_entity", "target", "status", "submitted_at")
    list_filter = ("target", "status")
    date_hierarchy = "submitted_at"
    raw_id_fields = ("assessment",)

    @admin.display(description="Entity")
    def get_entity(self, obj):
        return obj.assessment.entity.organisation_name
