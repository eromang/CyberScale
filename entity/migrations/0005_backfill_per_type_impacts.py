from django.db import migrations


def backfill(apps, schema_editor):
    Assessment = apps.get_model("entity", "Assessment")
    for a in Assessment.objects.all():
        if a.affected_entity_types and not a.per_type_impacts:
            a.per_type_impacts = [
                {
                    "sector": t["sector"],
                    "entity_type": t["entity_type"],
                    "ms_affected": a.ms_affected or [],
                    "service_impact": a.service_impact,
                    "data_impact": a.data_impact,
                    "safety_impact": a.safety_impact,
                    "financial_impact": a.financial_impact,
                    "affected_persons_count": a.affected_persons_count,
                    "impact_duration_hours": a.impact_duration_hours,
                    "sector_specific": a.sector_specific or {},
                }
                for t in a.affected_entity_types
            ]
            a.save()


class Migration(migrations.Migration):
    dependencies = [
        ("entity", "0004_per_type_impacts"),
    ]
    operations = [
        migrations.RunPython(backfill, migrations.RunPython.noop),
    ]
