from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Count, Sum
from .models import Company, UserProfile, IPScan, URLScan, FileScan, CompanyInvoice
from .forms import CompanyRegistrationForm, CompanySettingsForm, CompanyUserForm
from django.contrib.auth.models import User
import secrets
import string

@login_required
def register_company(request):
    """Register a new company account"""
    if request.method == 'POST':
        form = CompanyRegistrationForm(request.POST)
        if form.is_valid():
            company = form.save(commit=False)
            
            # Generate API Key
            api_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
            company.api_key = api_key
            
            # Set features based on plan
            if company.plan == 'basic':
                company.monthly_scan_limit = 500
                company.can_export_reports = True
            elif company.plan == 'professional':
                company.monthly_scan_limit = 5000
                company.can_export_reports = True
                company.can_use_api = True
                company.can_access_advanced_analytics = True
            elif company.plan == 'enterprise':
                company.monthly_scan_limit = 999999
                company.can_export_reports = True
                company.can_use_api = True
                company.can_access_advanced_analytics = True
                company.has_priority_support = True
                company.max_users = 50
            else:
                company.monthly_scan_limit = 100
            
            company.save()
            
            # Update user profile to company admin
            profile = request.user.profile
            profile.user_type = 'company_admin'
            profile.company = company
            profile.save()
            
            messages.success(request, f"Company {company.name} registered successfully!")
            return redirect('analyzer:company_dashboard')
    else:
        form = CompanyRegistrationForm()
    
    return render(request, 'analyzer/company/register.html', {'form': form})

@login_required
def company_dashboard(request):
    """Company dashboard with analytics"""
    profile = request.user.profile
    
    if not profile.is_company_account():
        messages.error(request, "Access denied. Company account required.")
        return redirect('analyzer:home')
    
    company = profile.company
    
    # Get statistics for the company
    total_ip_scans = IPScan.objects.filter(company=company).count()
    total_url_scans = URLScan.objects.filter(company=company).count()
    total_file_scans = FileScan.objects.filter(company=company).count()
    
    # Get recent scans
    recent_scans = []
    recent_scans.extend(IPScan.objects.filter(company=company)[:5])
    recent_scans.extend(URLScan.objects.filter(company=company)[:5])
    recent_scans.extend(FileScan.objects.filter(company=company)[:5])
    recent_scans.sort(key=lambda x: x.created_at, reverse=True)
    recent_scans = recent_scans[:10]
    
    # Get team members
    team_members = UserProfile.objects.filter(company=company)
    
    # Get monthly usage
    current_month = timezone.now().month
    monthly_usage = {
        'ip': IPScan.objects.filter(company=company, created_at__month=current_month).count(),
        'url': URLScan.objects.filter(company=company, created_at__month=current_month).count(),
        'file': FileScan.objects.filter(company=company, created_at__month=current_month).count(),
    }
    
    context = {
        'company': company,
        'profile': profile,
        'total_ip_scans': total_ip_scans,
        'total_url_scans': total_url_scans,
        'total_file_scans': total_file_scans,
        'recent_scans': recent_scans,
        'team_members': team_members,
        'monthly_usage': monthly_usage,
        'remaining_scans': company.get_remaining_scans(),
        'usage_percentage': (company.scans_used_this_month / company.monthly_scan_limit) * 100 if company.monthly_scan_limit > 0 else 0,
    }
    
    return render(request, 'analyzer/company/dashboard.html', context)

@login_required
def company_settings(request):
    """Company settings and configuration"""
    profile = request.user.profile
    
    if not profile.is_company_account() or profile.user_type != 'company_admin':
        messages.error(request, "Access denied. Company admin required.")
        return redirect('analyzer:home')
    
    company = profile.company
    
    if request.method == 'POST':
        form = CompanySettingsForm(request.POST, request.FILES, instance=company)
        if form.is_valid():
            form.save()
            messages.success(request, "Company settings updated successfully!")
            return redirect('analyzer:company_settings')
    else:
        form = CompanySettingsForm(instance=company)
    
    context = {
        'company': company,
        'form': form,
    }
    
    return render(request, 'analyzer/company/settings.html', context)

@login_required
def manage_team(request):
    """Manage company team members"""
    profile = request.user.profile
    
    if not profile.is_company_account() or profile.user_type != 'company_admin':
        messages.error(request, "Access denied. Company admin required.")
        return redirect('analyzer:home')
    
    company = profile.company
    
    if request.method == 'POST':
        form = CompanyUserForm(request.POST)
        if form.is_valid():
            # Create new user for team member
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            
            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already exists.")
            elif User.objects.filter(email=email).exists():
                messages.error(request, "Email already exists.")
            else:
                user = User.objects.create_user(username=username, email=email, password=password)
                user_profile = user.profile
                user_profile.user_type = 'company_member'
                user_profile.company = company
                user_profile.save()
                
                messages.success(request, f"Team member {username} added successfully!")
                return redirect('analyzer:manage_team')
    else:
        form = CompanyUserForm()
    
    team_members = UserProfile.objects.filter(company=company)
    
    context = {
        'company': company,
        'team_members': team_members,
        'form': form,
        'max_users': company.max_users,
        'current_users': team_members.count(),
    }
    
    return render(request, 'analyzer/company/team.html', context)

@login_required
def company_billing(request):
    """Company billing and invoices"""
    profile = request.user.profile
    
    if not profile.is_company_account() or profile.user_type != 'company_admin':
        messages.error(request, "Access denied. Company admin required.")
        return redirect('analyzer:home')
    
    company = profile.company
    invoices = CompanyInvoice.objects.filter(company=company).order_by('-created_at')
    
    context = {
        'company': company,
        'invoices': invoices,
    }
    
    return render(request, 'analyzer/company/billing.html', context)

@login_required
def company_analytics(request):
    """Advanced analytics for company"""
    profile = request.user.profile
    
    if not profile.is_company_account():
        messages.error(request, "Access denied. Company account required.")
        return redirect('analyzer:home')
    
    company = profile.company
    
    if not company.can_access_advanced_analytics:
        messages.warning(request, "Upgrade your plan to access advanced analytics.")
        return redirect('analyzer:company_dashboard')
    
    # Get monthly stats for the last 12 months
    monthly_stats = []
    for i in range(12):
        month = timezone.now().replace(day=1) - timezone.timedelta(days=30*i)
        stats = {
            'month': month.strftime('%B %Y'),
            'ip': IPScan.objects.filter(company=company, created_at__year=month.year, created_at__month=month.month).count(),
            'url': URLScan.objects.filter(company=company, created_at__year=month.year, created_at__month=month.month).count(),
            'file': FileScan.objects.filter(company=company, created_at__year=month.year, created_at__month=month.month).count(),
        }
        monthly_stats.append(stats)
    
    # Get top risk scores
    high_risk_ips = IPScan.objects.filter(company=company, risk_score__gt=70).order_by('-risk_score')[:10]
    
    context = {
        'company': company,
        'monthly_stats': monthly_stats,
        'high_risk_ips': high_risk_ips,
    }
    
    return render(request, 'analyzer/company/analytics.html', context)