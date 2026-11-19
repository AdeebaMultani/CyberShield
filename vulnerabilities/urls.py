from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),

    path(
        'vulnerabilities/',
        views.vulnerability_list,
        name='vulnerability_list'
    ),

    path(
        'vulnerabilities/<str:cve_id>/',
        views.vulnerability_detail,
        name='vulnerability_detail'
    ),
]