from django.db import migrations


def populate_entity_types(apps, schema_editor):
    """Create EntityType records from existing Entity sector/entity_type fields."""
    Entity = apps.get_model("entity", "Entity")
    EntityType = apps.get_model("entity", "EntityType")
    Assessment = apps.get_model("entity", "Assessment")

    for entity in Entity.objects.all():
        if entity.sector and entity.entity_type:
            EntityType.objects.get_or_create(
                entity=entity,
                entity_type=entity.entity_type,
                defaults={"sector": entity.sector},
            )

    for assessment in Assessment.objects.all():
        if assessment.sector and assessment.entity_type:
            assessment.affected_entity_types = [
                {"sector": assessment.sector, "entity_type": assessment.entity_type}
            ]
            if assessment.status == "completed":
                assessment.assessment_results = [{
                    "sector": assessment.sector,
                    "entity_type": assessment.entity_type,
                    "significant_incident": assessment.result_significance,
                    "significance_label": assessment.result_significance_label,
                    "model": assessment.result_model,
                    "triggered_criteria": assessment.result_criteria,
                    "framework": assessment.result_framework,
                    "competent_authority": assessment.result_competent_authority,
                    "early_warning": assessment.result_early_warning,
                }]
            assessment.save()


def reverse_populate(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("entity", "0002_entitytype_multi"),
    ]

    operations = [
        migrations.RunPython(populate_entity_types, reverse_populate),
    ]
