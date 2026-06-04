from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
import secrets
import string

# =====================================================================
# 🏢 COMPANY MODEL
# =====================================================================
class Company(models.Model):
    PLAN_CHOICES = (
        ('free', 'Free Plan - 100 scans/month'),
        ('basic', 'Basic Plan - 500 scans/month'),
        ('professional', 'Professional Plan - 5000 scans/month'),
        ('enterprise', 'Enterprise Plan - Unlimited scans'),
    )
    
    ESTABLISHMENT_TYPE = (
        ('startup', 'Startup'),
        ('sme', 'SME'),
        ('corporation', 'Corporation'),
        ('government', 'Government'),
        ('education', 'Education'),
        ('nonprofit', 'Non-Profit'),
    )
    
    # Basic Info
    name = models.CharField(max_length=200, unique=True)
    registration_number = models.CharField(max_length=100, unique=True, blank=True, null=True)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20)
    website = models.URLField(blank=True, null=True)
    address = models.TextField()
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=100, default="Morocco")
    establishment_type = models.CharField(max_length=50, choices=ESTABLISHMENT_TYPE, default='startup')
    
    # Subscription
    plan = models.CharField(max_length=20, choices=PLAN_CHOICES, default='free')
    subscription_start = models.DateTimeField(auto_now_add=True)
    subscription_end = models.DateTimeField(null=True, blank=True)
    
    # Quotas
    monthly_scan_limit = models.IntegerField(default=100)
    scans_used_this_month = models.IntegerField(default=0)
    last_reset_date = models.DateTimeField(auto_now=True)
    
    # API
    api_key = models.CharField(max_length=100, unique=True, null=True, blank=True)
    api_requests_count = models.IntegerField(default=0)
    
    # Features
    can_access_advanced_analytics = models.BooleanField(default=False)
    can_export_reports = models.BooleanField(default=False)
    can_use_api = models.BooleanField(default=False)
    has_priority_support = models.BooleanField(default=False)
    
    # Team
    max_users = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    # Branding
    logo = models.ImageField(upload_to='company_logos/', null=True, blank=True)
    notes = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.name} - {self.get_plan_display()}"
    
    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        super().save(*args, **kwargs)
    
    def has_scan_quota(self):
        return self.scans_used_this_month < self.monthly_scan_limit
    
    def increment_scan_count(self):
        self.scans_used_this_month += 1
        self.save()
    
    def get_remaining_scans(self):
        return max(0, self.monthly_scan_limit - self.scans_used_this_month)
    
    class Meta:
        verbose_name_plural = "Companies"
        ordering = ['-created_at']


# =====================================================================
# 👤 USER PROFILE
# =====================================================================
class UserProfile(models.Model):
    USER_TYPES = (
        ('personal', 'Personal User'),
        ('company_admin', 'Company Administrator'),
        ('company_member', 'Company Member'),
        ('super_admin', 'Super Administrator'),
    )
    
    SECTORS = (
        ('student', 'Student'),
        ('researcher', 'Researcher'),
        ('professional', 'Security Professional'),
        ('pentester', 'Penetration Tester'),
        ('soc_analyst', 'SOC Analyst'),
        ('other', 'Other'),
    )
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    user_type = models.CharField(max_length=20, choices=USER_TYPES, default='personal')
    
    # Company Relationship
    company = models.ForeignKey(Company, on_delete=models.CASCADE, null=True, blank=True, related_name='members')
    
    # Personal Information
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    establishment = models.CharField(max_length=200, blank=True, null=True, help_text="School/University/Company Name")
    sector = models.CharField(max_length=50, choices=SECTORS, blank=True, null=True)
    
    # Account Status
    api_requests_count = models.IntegerField(default=0)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    email_notifications = models.BooleanField(default=True)
    api_key = models.CharField(max_length=100, unique=True, null=True, blank=True)
    
    # Preferences
    language = models.CharField(max_length=10, default='en')
    theme = models.CharField(max_length=20, default='dark')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.get_user_type_display()}"
    
    def is_company_account(self):
        return self.user_type in ['company_admin', 'company_member']
    
    def can_access_company_features(self):
        if self.is_company_account() and self.company:
            return self.company.is_active
        return False

    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        super().save(*args, **kwargs)


# =====================================================================
# 🛰️ IP SCAN
# =====================================================================
class IPScan(models.Model):
    ip = models.CharField(max_length=100)
    risk_score = models.IntegerField()
    status = models.CharField(max_length=50)
    abuse_score = models.IntegerField(default=0)
    country = models.CharField(max_length=100, null=True, blank=True)
    raw_abuse = models.JSONField(null=True, blank=True)
    raw_shodan = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='ip_scans')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, null=True, blank=True, related_name='ip_scans')

    def __str__(self):
        return f"IP: {self.ip} // Score: {self.risk_score}%"


# =====================================================================
# 🌐 URL SCAN
# =====================================================================
class URLScan(models.Model):
    url = models.URLField(max_length=500)
    risk_score = models.IntegerField()
    status = models.CharField(max_length=50)
    malicious_count = models.IntegerField(default=0)
    harmless_count = models.IntegerField(default=0)
    suspicious_count = models.IntegerField(default=0)
    raw_virustotal = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='url_scans')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, null=True, blank=True, related_name='url_scans')

    def __str__(self):
        return f"URL: {self.url} // Status: {self.status}"


# =====================================================================
# 🗂️ FILE SCAN
# =====================================================================
class FileScan(models.Model):
    file_name = models.CharField(max_length=255)
    file_size = models.CharField(max_length=50)
    sha256 = models.CharField(max_length=64, db_index=True)
    verdict = models.CharField(max_length=50, default="clean")
    risk_score = models.IntegerField(default=0)
    malicious_count = models.IntegerField(default=0)
    suspicious_count = models.IntegerField(default=0)
    clean_count = models.IntegerField(default=0)
    total_engines = models.IntegerField(default=0)
    file_type = models.CharField(max_length=100, default="Generic Binary")
    created_at = models.DateTimeField(auto_now_add=True)
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='file_scans')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, null=True, blank=True, related_name='file_scans')

    def __str__(self):
        return f"File: {self.file_name} // SHA256: {self.sha256[:10]}..."


# =====================================================================
# 🔏 BLACKLISTED IP
# =====================================================================
class BlacklistedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, default="Suspicious Activity")
    added_at = models.DateTimeField(auto_now_add=True)
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='blacklisted_ips')
    company = models.ForeignKey(Company, on_delete=models.CASCADE, null=True, blank=True, related_name='blacklisted_ips')

    def __str__(self):
        return f"BANNED IP: {self.ip_address}"


# =====================================================================
# 🪤 HONEYPOT MODELS
# =====================================================================
class HoneypotPort(models.Model):
    port = models.IntegerField(unique=True)
    service_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Port {self.port} ({self.service_name}) - {'ACTIVE' if self.is_active else 'INACTIVE'}"


class HoneypotLog(models.Model):
    ip_address = models.GenericIPAddressField()
    port = models.IntegerField()
    service_name = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.TextField(blank=True, null=True)
    payload = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.ip_address} scanned {self.port} ({self.service_name}) at {self.timestamp}"


# =====================================================================
# 📊 COMPANY INVOICE
# =====================================================================
class CompanyInvoice(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    )
    
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='invoices')
    invoice_number = models.CharField(max_length=100, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='MAD')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    payment_method = models.CharField(max_length=50, blank=True)
    payment_date = models.DateTimeField(null=True, blank=True)
    due_date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    pdf_file = models.FileField(upload_to='invoices/', null=True, blank=True)

    def __str__(self):
        return f"Invoice {self.invoice_number} - {self.company.name}"


# =====================================================================
# 🔔 SIGNALS
# =====================================================================
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()