from django.contrib import admin
from .models import Vulnerability

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):

    list_display = (
        'cve_id',
        'severity',
        'cvss_score',
        'affected_product',
        'published_date'
    )

    list_filter = ('severity', 'published_date')

    search_fields = ('cve_id', 'description', 'affected_product')

    ordering = ('-published_date',)