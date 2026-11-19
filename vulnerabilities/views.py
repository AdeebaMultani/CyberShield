from django.db.models import Count, Q
from django.shortcuts import render, get_object_or_404
from .models import Vulnerability
from django.core.paginator import Paginator

def dashboard(request):

    total_vulnerabilities = Vulnerability.objects.count()

    critical_count = Vulnerability.objects.filter(
        severity='CRITICAL'
    ).count()

    high_count = Vulnerability.objects.filter(
        severity='HIGH'
    ).count()

    medium_count = Vulnerability.objects.filter(
        severity='MEDIUM'
    ).count()

    low_count = Vulnerability.objects.filter(
        severity='LOW'
    ).count()

    recent_vulnerabilities = Vulnerability.objects.order_by(
        '-published_date'
    )[:5]

    severity_data = Vulnerability.objects.values(
        'severity'
    ).annotate(
        total=Count('id')
    ).order_by('severity')

    context = {
        'total_vulnerabilities': total_vulnerabilities,
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'recent_vulnerabilities': recent_vulnerabilities,
        'severity_data': list(severity_data),
    }

    return render(request, 'dashboard.html', context)


def vulnerability_list(request):

    query = request.GET.get('q', '').strip()
    severity = request.GET.get('severity', '').upper()

    vulnerabilities = Vulnerability.objects.all().order_by(
        '-published_date', 'cve_id'
    )

    # Search across CVE ID, description and product
    if query:
        vulnerabilities = vulnerabilities.filter(
            Q(cve_id__icontains=query) |
            Q(description__icontains=query) |
            Q(affected_product__icontains=query)
        )

    # Validate severity selection
    valid_severities = {
        choice[0] for choice in Vulnerability.SEVERITY_CHOICES
    }

    if severity in valid_severities:
        vulnerabilities = vulnerabilities.filter(
            severity=severity
        )
    else:
        severity = ''

    # Divide records into pages
    paginator = Paginator(vulnerabilities, 5)

    page_number = request.GET.get('page')

    page_obj = paginator.get_page(page_number)

    context = {
        'vulnerabilities': page_obj,
        'page_obj': page_obj,
        'query': query,
        'selected_severity': severity,
        'total_results': paginator.count,
        'severity_choices': Vulnerability.SEVERITY_CHOICES,
    }

    return render(
        request,
        'vulnerability_list.html',
        context
    )


def vulnerability_detail(request, cve_id):

    vulnerability = get_object_or_404(
        Vulnerability,
        cve_id=cve_id
    )

    return render(
        request,
        'vulnerability_detail.html',
        {'vulnerability': vulnerability}
    )
