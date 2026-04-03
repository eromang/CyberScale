from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("assess/", views.assessment_form_view, name="assessment_form"),
    path("assess/draft/<int:draft_pk>/", views.assessment_form_view, name="resume_draft"),
    path("assess/draft/<int:pk>/delete/", views.delete_draft_view, name="delete_draft"),
    path("assess/<int:pk>/", views.assessment_result_view, name="assessment_result"),
    path("assess/<int:pk>/pdf/", views.assessment_pdf_view, name="assessment_pdf"),
    path("assess/<int:pk>/misp-json/", views.assessment_misp_json_view, name="assessment_misp_json"),
    path("htmx/entity-types/", views.entity_types_for_sector, name="htmx_entity_types"),
]
