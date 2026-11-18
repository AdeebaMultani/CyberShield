from django.db import models

class Vulnerability(models.Model):

    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
        ('UNKNOWN', 'Unknown'),
    ]

    cve_id = models.CharField(max_length=20, unique=True)

    description = models.TextField()

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default='UNKNOWN'
    )

    cvss_score = models.DecimalField(
        max_digits=3,
        decimal_places=1,
        null=True,
        blank=True
    )

    affected_product = models.CharField(
        max_length=255,
        blank=True
    )

    published_date = models.DateField(
        null=True,
        blank=True
    )

    source_url = models.URLField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.cve_id

    class Meta:
        ordering = ['-published_date']