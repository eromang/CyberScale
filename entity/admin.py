from django.contrib import admin

from .models import Assessment, Entity, Submission


@admin.register(Entity)
class EntityAdmin(admin.ModelAdmin):
    list_display = ("organisation_name", "sector", "entity_type", "ms_established", "competent_authority")
    list_filter = ("sector", "ms_established")
    search_fields = ("organisation_name",)


@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = ("id", "entity", "status", "result_significance_label", "result_model", "created_at")
    list_filter = ("status", "result_model", "sector")
    readonly_fields = ("result_significance", "result_significance_label", "result_model", "result_criteria", "result_raw")


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ("id", "assessment", "target", "status", "submitted_at")
    list_filter = ("target", "status")
