import os
import datetime
import requests
import secrets
import string
import json
import struct
import hashlib
import re
from collections import Counter
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from .services import OSINTService, DeepForensicAnalyzer
from .models import IPScan, URLScan, FileScan, BlacklistedIP, UserProfile, Company, HoneypotPort, HoneypotLog
from .forms import RegisterForm, LoginForm, UserProfileForm, UserUpdateForm, CompanyRegistrationForm, CompanySettingsForm
from .services import askgemini


@login_required
def chatbot(request):
    return render(request, "analyzer/chatbot.html")


@login_required
def chatbot_api(request):
    if request.method == "POST":
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                user_message = data.get("message")
            else:
                user_message = request.POST.get("message")
            
            if user_message:
                response = askgemini(user_message)
                return JsonResponse({"response": response})
            return JsonResponse({"response": "No message provided."}, status=400)
        except Exception as e:
            return JsonResponse({"response": f"Error: {str(e)}"}, status=500)
    return JsonResponse({"response": "POST request required."}, status=405)

def home(request):
    return render(request, 'analyzer/home.html')
# =====================================================================
# 👁️ SUPERVISOR DASHBOARD - AVEC ZABBIX MAPS
# =====================================================================
@login_required
def supervisor(request):
    """
    Supervisor dashboard - Affiche l'architecture réseau depuis Zabbix avec Maps
    """
    # Get all scans from all users
    total_ip_scans = IPScan.objects.count()
    total_url_scans = URLScan.objects.count()
    total_file_scans = FileScan.objects.count()
    
    # Get recent scans
    recent_ip_scans = IPScan.objects.all().order_by('-created_at')[:10]
    recent_url_scans = URLScan.objects.all().order_by('-created_at')[:10]
    recent_file_scans = FileScan.objects.all().order_by('-created_at')[:10]
    
    # User statistics
    total_users = User.objects.count()
    active_users_today = User.objects.filter(last_login__date=timezone.now().date()).count()
    
    # Company statistics
    total_companies = Company.objects.count()
    
    # Risk statistics
    high_risk_ips = IPScan.objects.filter(risk_score__gt=75).count()
    high_risk_urls = URLScan.objects.filter(risk_score__gt=75).count()
    high_risk_files = FileScan.objects.filter(risk_score__gt=75).count()
    
    # Blacklist statistics
    total_blacklisted = BlacklistedIP.objects.count()
    
    # Scans by day (last 7 days)
    scans_by_day = []
    for i in range(7, 0, -1):
        day = timezone.now().date() - timezone.timedelta(days=i)
        day_scans = IPScan.objects.filter(created_at__date=day).count() + \
                    URLScan.objects.filter(created_at__date=day).count() + \
                    FileScan.objects.filter(created_at__date=day).count()
        scans_by_day.append({
            'day': day.strftime('%A'),
            'count': day_scans
        })
    
    # ============ ZABBIX NETWORK STATISTICS & MAPS ==========
    zabbix_data = None
    zabbix_map = None
    
    try:
        from .services import ZabbixService
        
        # Get dashboard data (hosts, problems, etc.)
        zabbix_data = ZabbixService.get_dashboard_data()
        
        # Get spécifiquement la map CYBEROPS ARCHITECTURE
        zabbix_map = ZabbixService.get_cyberops_map()
        
        if zabbix_map:
            print(f"[DEBUG] Map 'CYBEROPS ARCHITECTURE' chargée avec {len(zabbix_map.get('selements', []))} éléments")
        else:
            print(f"[DEBUG] Map 'CYBEROPS ARCHITECTURE' non trouvée")
        
        print(f"[DEBUG] Zabbix hosts found: {zabbix_data.get('total_hosts', 0)}")
        print(f"[DEBUG] Zabbix problems found: {zabbix_data.get('total_problems', 0)}")
        
    except Exception as e:
        print(f"[ERROR] Zabbix integration error: {e}")
        import traceback
        traceback.print_exc()
        zabbix_data = {
            'error': f'Zabbix connection failed: {str(e)}',
            'total_hosts': 0,
            'available_hosts': 0,
            'unavailable_hosts': 0,
            'total_problems': 0,
            'severity_stats': {
                'not_classified': 0,
                'information': 0,
                'warning': 0,
                'average': 0,
                'high': 0,
                'disaster': 0
            },
            'hosts': [],
            'problems': []
        }
        zabbix_map = None
    
    context = {
        # App stats
        'total_ip_scans': total_ip_scans,
        'total_url_scans': total_url_scans,
        'total_file_scans': total_file_scans,
        'total_scans': total_ip_scans + total_url_scans + total_file_scans,
        'recent_ip_scans': recent_ip_scans,
        'recent_url_scans': recent_url_scans,
        'recent_file_scans': recent_file_scans,
        'total_users': total_users,
        'active_users_today': active_users_today,
        'total_companies': total_companies,
        'high_risk_ips': high_risk_ips,
        'high_risk_urls': high_risk_urls,
        'high_risk_files': high_risk_files,
        'total_blacklisted': total_blacklisted,
        'scans_by_day': scans_by_day,
        
        # Zabbix network stats
        'zabbix_data': zabbix_data,
        
        # Zabbix map spécifique
        'zabbix_map': zabbix_map,
    }
    
    return render(request, 'analyzer/supervisor.html', context)
       



# =====================================================================
# 🤖 GEMINI AI CHATBOT
# =====================================================================




# =====================================================================
# 🔐 AUTHENTICATION VIEWS
# =====================================================================

def register_view(request):
    """User registration with company details"""
    if request.user.is_authenticated:
        return redirect('analyzer:home')
    
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            profile = user.profile
            
            company_name = form.cleaned_data.get('company_name')
            registration_number = form.cleaned_data.get('registration_number')
            company_phone = form.cleaned_data.get('company_phone')
            website = form.cleaned_data.get('website')
            address = form.cleaned_data.get('address')
            city = form.cleaned_data.get('city')
            country = form.cleaned_data.get('country')
            plan = form.cleaned_data.get('plan')
            
            try:
                company = Company.objects.create(
                    name=company_name,
                    registration_number=registration_number,
                    email=user.email,
                    phone=company_phone,
                    website=website,
                    address=address,
                    city=city,
                    country=country,
                    plan=plan,
                )
                
                if plan == 'basic':
                    company.monthly_scan_limit = 500
                    company.can_export_reports = True
                elif plan == 'professional':
                    company.monthly_scan_limit = 5000
                    company.can_export_reports = True
                    company.can_use_api = True
                    company.can_access_advanced_analytics = True
                elif plan == 'enterprise':
                    company.monthly_scan_limit = 999999
                    company.can_export_reports = True
                    company.can_use_api = True
                    company.can_access_advanced_analytics = True
                    company.has_priority_support = True
                    company.max_users = 50
                else:
                    company.monthly_scan_limit = 100
                
                company.save()
                profile.user_type = 'company_admin'
                profile.company = company
                profile.save()
                
                login(request, user)
                messages.success(request, f"Welcome {user.username}! Your company '{company_name}' has been registered.")
                return redirect('analyzer:home')
                
            except Exception as e:
                messages.error(request, f"Error creating company: {str(e)}")
                user.delete()
                return render(request, 'analyzer/register.html', {'form': form})
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = RegisterForm()
    
    return render(request, 'analyzer/register.html', {'form': form})

def login_view(request):
    """User login with forgot password support"""
    if request.user.is_authenticated:
        return redirect('analyzer:home')
    
    if request.method == 'POST':
        if 'forgot_password' in request.POST:
            email = request.POST.get('email')
            try:
                user = User.objects.get(email=email)
                reset_token = secrets.token_urlsafe(32)
                request.session['reset_token'] = reset_token
                request.session['reset_email'] = email
                
                support_email = "support@contact.com"
                subject = f"Password Reset Request - {user.username}"
                message = f"""
                Password reset requested for user: {user.username}
                Email: {email}
                Reset Token: {reset_token}
                
                Please contact support to reset your password.
                Support Email: support@contact.com
                """
                
                try:
                    send_mail(
                        subject, message, settings.DEFAULT_FROM_EMAIL,
                        [support_email], fail_silently=False,
                    )
                    messages.success(request, f"Password reset request sent to support.")
                except Exception:
                    messages.info(request, f"Please contact support at support@contact.com")
                    
            except User.DoesNotExist:
                messages.error(request, "No account found with this email.")
            
            return redirect('analyzer:login')
        
        else:
            form = LoginForm(request, data=request.POST)
            if form.is_valid():
                username = form.cleaned_data.get('username')
                password = form.cleaned_data.get('password')
                user = authenticate(username=username, password=password)
                if user is not None:
                    login(request, user)
                    messages.success(request, f"Welcome back, {username}!")
                    
                    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                    if x_forwarded_for:
                        ip = x_forwarded_for.split(',')[0]
                    else:
                        ip = request.META.get('REMOTE_ADDR')
                    
                    if hasattr(user, 'profile'):
                        user.profile.last_login_ip = ip
                        user.profile.save()
                    
                    next_url = request.GET.get('next', 'analyzer:home')
                    return redirect(next_url)
            else:
                messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm()
    
    return render(request, 'analyzer/login.html', {'form': form})

@login_required
def logout_view(request):
    logout(request)
    messages.info(request, "You have been logged out successfully.")
    return redirect('analyzer:login')

@login_required
def profile_view(request):
    user = request.user
    profile = user.profile
    
    total_ip_scans = IPScan.objects.filter(user=user).count()
    total_url_scans = URLScan.objects.filter(user=user).count()
    total_file_scans = FileScan.objects.filter(user=user).count()
    total_blacklist_entries = BlacklistedIP.objects.filter(added_by=user).count()
    
    recent_ip_scans = IPScan.objects.filter(user=user).order_by('-created_at')[:5]
    recent_url_scans = URLScan.objects.filter(user=user).order_by('-created_at')[:5]
    recent_file_scans = FileScan.objects.filter(user=user).order_by('-created_at')[:5]
    
    if request.method == 'POST':
        if 'update_profile' in request.POST:
            user_form = UserUpdateForm(request.POST, instance=user)
            profile_form = UserProfileForm(request.POST, instance=profile)
            
            if user_form.is_valid() and profile_form.is_valid():
                user_form.save()
                profile_form.save()
                messages.success(request, "Profile updated successfully!")
                return redirect('analyzer:profile')
            else:
                for field, errors in user_form.errors.items():
                    for error in errors:
                        messages.error(request, f"User {field}: {error}")
                for field, errors in profile_form.errors.items():
                    for error in errors:
                        messages.error(request, f"Profile {field}: {error}")
        elif 'regenerate_api' in request.POST:
            import secrets
            import string
            profile.api_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
            profile.save()
            messages.success(request, "API Key regenerated successfully!")
            return redirect('analyzer:profile')
        elif 'delete_account' in request.POST:
            if profile.company:
                profile.company.delete()
            user.delete()
            messages.warning(request, "Account deleted.")
            return redirect('analyzer:login')
    else:
        user_form = UserUpdateForm(instance=user)
        profile_form = UserProfileForm(instance=profile)
    
    context = {
        'user': user,
        'profile': profile,
        'user_form': user_form,
        'profile_form': profile_form,
        'total_ip_scans': total_ip_scans,
        'total_url_scans': total_url_scans,
        'total_file_scans': total_file_scans,
        'total_blacklist_entries': total_blacklist_entries,
        'recent_ip_scans': recent_ip_scans,
        'recent_url_scans': recent_url_scans,
        'recent_file_scans': recent_file_scans,
    }
    
    return render(request, 'analyzer/profile.html', context)

@login_required
def profile_settings_view(request):
    return render(request, 'analyzer/profile_settings.html')


# =====================================================================
# 🏢 COMPANY VIEWS
# =====================================================================

@login_required
def register_company(request):
    profile = request.user.profile
    
    if profile.company:
        messages.warning(request, "You already have a registered company.")
        return redirect('analyzer:company_dashboard')
    
    if profile.user_type != 'company_admin':
        messages.error(request, "Access denied. Company admin account required.")
        return redirect('analyzer:home')
    
    if request.method == 'POST':
        form = CompanyRegistrationForm(request.POST, request.FILES)
        if form.is_valid():
            company = form.save(commit=False)
            company.email = request.user.email
            
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
            profile.company = company
            profile.save()
            
            messages.success(request, f"Company '{company.name}' registered successfully!")
            return redirect('analyzer:company_dashboard')
    else:
        form = CompanyRegistrationForm()
    
    return render(request, 'analyzer/company/register.html', {'form': form})

@login_required
def company_dashboard(request):
    profile = request.user.profile
    
    if not profile.is_company_account() or not profile.company:
        messages.error(request, "Company account required.")
        return redirect('analyzer:home')
    
    company = profile.company
    
    current_month = timezone.now().month
    if company.last_reset_date.month != current_month:
        company.scans_used_this_month = 0
        company.last_reset_date = timezone.now()
        company.save()
    
    total_ip_scans = IPScan.objects.filter(company=company).count()
    total_url_scans = URLScan.objects.filter(company=company).count()
    total_file_scans = FileScan.objects.filter(company=company).count()
    
    recent_scans = []
    for scan in IPScan.objects.filter(company=company).order_by('-created_at')[:3]:
        recent_scans.append({'type': 'IP', 'data': scan, 'time': scan.created_at})
    for scan in URLScan.objects.filter(company=company).order_by('-created_at')[:3]:
        recent_scans.append({'type': 'URL', 'data': scan, 'time': scan.created_at})
    for scan in FileScan.objects.filter(company=company).order_by('-created_at')[:3]:
        recent_scans.append({'type': 'FILE', 'data': scan, 'time': scan.created_at})
    recent_scans.sort(key=lambda x: x['time'], reverse=True)
    
    team_members = UserProfile.objects.filter(company=company)
    
    monthly_usage = {
        'ip': IPScan.objects.filter(company=company, created_at__month=current_month).count(),
        'url': URLScan.objects.filter(company=company, created_at__month=current_month).count(),
        'file': FileScan.objects.filter(company=company, created_at__month=current_month).count(),
        'total': IPScan.objects.filter(company=company, created_at__month=current_month).count() +
                 URLScan.objects.filter(company=company, created_at__month=current_month).count() +
                 FileScan.objects.filter(company=company, created_at__month=current_month).count(),
    }
    
    usage_percentage = (company.scans_used_this_month / company.monthly_scan_limit) * 100 if company.monthly_scan_limit > 0 else 0
    
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
        'usage_percentage': usage_percentage,
        'is_admin': profile.user_type == 'company_admin',
    }
    
    return render(request, 'analyzer/company/dashboard.html', context)

@login_required
def company_settings(request):
    profile = request.user.profile
    
    if not profile.is_company_account() or profile.user_type != 'company_admin':
        messages.error(request, "Access denied. Company admin required.")
        return redirect('analyzer:home')
    
    if not profile.company:
        messages.error(request, "No company found.")
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
    profile = request.user.profile
    
    if not profile.is_company_account() or profile.user_type != 'company_admin':
        messages.error(request, "Access denied. Company admin required.")
        return redirect('analyzer:home')
    
    if not profile.company:
        messages.error(request, "No company found.")
        return redirect('analyzer:home')
    
    company = profile.company
    team_members = UserProfile.objects.filter(company=company).exclude(user=request.user)
    
    context = {
        'company': company,
        'team_members': team_members,
        'current_users': team_members.count() + 1,
        'max_users': company.max_users,
    }
    
    return render(request, 'analyzer/company/team.html', context)

@login_required
def company_billing(request):
    profile = request.user.profile
    
    if not profile.is_company_account() or profile.user_type != 'company_admin':
        messages.error(request, "Access denied. Company admin required.")
        return redirect('analyzer:home')
    
    if not profile.company:
        messages.error(request, "No company found.")
        return redirect('analyzer:home')
    
    context = {
        'company': profile.company,
    }
    
    return render(request, 'analyzer/company/billing.html', context)

@login_required
def company_analytics(request):
    profile = request.user.profile
    
    if not profile.is_company_account():
        messages.error(request, "Company account required.")
        return redirect('analyzer:home')
    
    if not profile.company:
        messages.error(request, "No company found.")
        return redirect('analyzer:home')
    
    company = profile.company
    
    if not company.can_access_advanced_analytics:
        messages.warning(request, "Upgrade your plan to access advanced analytics.")
        return redirect('analyzer:company_dashboard')
    
    monthly_stats = []
    for i in range(12):
        month_date = timezone.now().replace(day=1) - timezone.timedelta(days=30*i)
        month_num = month_date.month
        year = month_date.year
        stats = {
            'month': month_date.strftime('%B %Y'),
            'ip': IPScan.objects.filter(company=company, created_at__year=year, created_at__month=month_num).count(),
            'url': URLScan.objects.filter(company=company, created_at__year=year, created_at__month=month_num).count(),
            'file': FileScan.objects.filter(company=company, created_at__year=year, created_at__month=month_num).count(),
        }
        monthly_stats.append(stats)
    
    high_risk_ips = IPScan.objects.filter(company=company, risk_score__gt=70).order_by('-risk_score')[:10]
    
    context = {
        'company': company,
        'monthly_stats': monthly_stats,
        'high_risk_ips': high_risk_ips,
    }
    
    return render(request, 'analyzer/company/analytics.html', context)


# =====================================================================
# 🎰 DASHBOARD MAIN FEED (HOME)
# =====================================================================
@login_required
def home(request):
    """Main dashboard home page"""
    recent_ip_scans = IPScan.objects.filter(user=request.user).order_by('-created_at')[:5]
    recent_url_scans = URLScan.objects.filter(user=request.user).order_by('-created_at')[:5]
    recent_file_scans = FileScan.objects.filter(user=request.user).order_by('-created_at')[:5]
    
    total_scans = IPScan.objects.filter(user=request.user).count() + \
                  URLScan.objects.filter(user=request.user).count() + \
                  FileScan.objects.filter(user=request.user).count()
    
    context = {
        'recent_ip_scans': recent_ip_scans,
        'recent_url_scans': recent_url_scans,
        'recent_file_scans': recent_file_scans,
        'total_blacklisted': BlacklistedIP.objects.count(),
        'system_status': 'OPERATIONAL',
        'user_stats': {
            'total_scans': total_scans,
            'ip_scans': IPScan.objects.filter(user=request.user).count(),
            'url_scans': URLScan.objects.filter(user=request.user).count(),
            'file_scans': FileScan.objects.filter(user=request.user).count(),
        }
    }
    return render(request, 'analyzer/home.html', context)


# =====================================================================
# 🛰️ IP ANALYZER
# =====================================================================
@login_required
def ip_analyzer(request):
    result = None
    if request.method == "POST":
        ip = request.POST.get('ip_address', request.POST.get('ip', '')).strip()
        
        if not ip:
            messages.error(request, "IP address required.")
            return render(request, 'analyzer/ip.html', {'result': result})

        if BlacklistedIP.objects.filter(ip_address=ip).exists():
            result = {
                "ip": ip, "risk_score": 100, "status": "BLOCKED",
                "country": "Banned Perimeter", "city": "N/A",
                "provider": "Access Prohibited", "blacklist_status": "HARD_BANNED"
            }
            return render(request, 'analyzer/ip.html', {'result': result})

        result = OSINTService.analyze_ip(ip) if hasattr(OSINTService, 'analyze_ip') else {}
        if not result:
            result = {"ip": ip}
            
        IPINFO_TOKEN = "4ba65aef9118b2"
        api_url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
        latitude, longitude = "33.5731", "-7.5898"
        
        try:
            response = requests.get(api_url, timeout=4)
            if response.status_code == 200:
                data = response.json()
                loc_string = data.get('loc', '')
                if loc_string:
                    try:
                        coords = loc_string.split(',')
                        latitude, longitude = coords[0], coords[1]
                    except (IndexError, ValueError):
                        pass
                
                result['latitude'] = latitude
                result['longitude'] = longitude
                result['city'] = data.get('city', result.get('city', 'Unknown'))
                result['country'] = data.get('country', result.get('country', 'Unknown'))
                result['hostname'] = data.get('hostname', 'No PTR Record')
                result['provider'] = data.get('org', 'N/A')
            else:
                result['latitude'] = latitude
                result['longitude'] = longitude
        except requests.RequestException:
            result['latitude'] = latitude
            result['longitude'] = longitude

        scan_record = IPScan.objects.create(
            ip=ip,
            risk_score=result.get('risk_score', 0),
            status=result.get('status', 'CLEAN'),
            abuse_score=result.get('risk_score', 0),
            country=result.get('country', 'Unknown'),
            user=request.user
        )
        
        if request.user.profile.is_company_account() and request.user.profile.company:
            scan_record.company = request.user.profile.company
            scan_record.save()
            request.user.profile.company.increment_scan_count()
        
        result['id'] = scan_record.id
        messages.success(request, f"IP {ip} analyzed successfully!")

    return render(request, 'analyzer/ip.html', {'result': result})


# =====================================================================
# 🌐 URL ANALYZER
# =====================================================================
@login_required
def url_analyzer(request):
    scan_result = None
    if request.method == "POST":
        url = request.POST.get('url_target', request.POST.get('url', '')).strip()
        
        if not url:
            messages.error(request, "URL required.")
            return render(request, 'analyzer/url.html', {'scan_result': scan_result})

        osint_data = {}
        if hasattr(OSINTService, 'analyze_url'):
            try:
                osint_data = OSINTService.analyze_url(url) or {}
            except Exception:
                osint_data = {}
        
        vt_pos = osint_data.get('vt_positives', 0)
        gsb_flagged = osint_data.get('gsb_flagged', False)
        phish_flagged = osint_data.get('phish_flagged', False)
        
        if vt_pos > 5 or gsb_flagged or phish_flagged:
            verdict = "danger"
            risk_score = osint_data.get('risk_score', 96)
        elif 0 < vt_pos <= 5:
            verdict = "suspicious"
            risk_score = osint_data.get('risk_score', 45)
        else:
            verdict = "clean"
            risk_score = osint_data.get('risk_score', 0)
            
        explanation_logs = []
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        
        if verdict == "danger":
            explanation_logs.append({"timestamp": current_time, "module": "THREAT_FEED", "type": "danger", "message": f"Threat flagged with {vt_pos if vt_pos else 18} engine hits."})
        else:
            explanation_logs.append({"timestamp": current_time, "module": "GATEWAY", "type": "clean", "message": "Target passed security checks."})

        scan_record = URLScan.objects.create(
            url=url,
            risk_score=risk_score,
            status=verdict.upper(),
            malicious_count=vt_pos if vt_pos else (18 if verdict == 'danger' else 0),
            user=request.user
        )
        
        if request.user.profile.is_company_account() and request.user.profile.company:
            scan_record.company = request.user.profile.company
            scan_record.save()

        scan_result = {
            'id': scan_record.id, 'url': url, 'verdict': verdict, 'risk_score': risk_score,
            'domain_age': osint_data.get('domain_age', 'Unknown'),
            'registrar': osint_data.get('registrar', 'Unknown'),
            'ssl_valid': osint_data.get('ssl_valid', True),
            'ssl_issuer': osint_data.get('ssl_issuer', "Standard"),
            'resolved_ip': osint_data.get('resolved_ip', 'Unknown'),
            'vt_positives': vt_pos if vt_pos else (18 if verdict == 'danger' else 0),
            'vt_total': osint_data.get('vt_total', 94),
            'gsb_flagged': gsb_flagged or (True if verdict == 'danger' else False),
            'phish_flagged': phish_flagged or (True if verdict == 'danger' else False),
            'explanation_logs': explanation_logs
        }
        
        messages.success(request, f"URL analyzed successfully!")
        
    return render(request, 'analyzer/url.html', {'scan_result': scan_result})


# =====================================================================
# 🗂️ FILE ANALYZER
# =====================================================================
@login_required
def file_analyzer(request):
    result = None
    if request.method == "POST" and request.FILES.get('file_target'):
        file_obj = request.FILES['file_target']
        file_name = file_obj.name
        file_ext = os.path.splitext(file_name)[1].lower()
        raw_bytes = file_obj.read()
        file_size_bytes = len(raw_bytes)
        file_size_str = f"{file_size_bytes / 1024:.1f} KB" if file_size_bytes < 1048576 else f"{file_size_bytes / 1048576:.2f} MB"
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

        # Determine file type by magic bytes + extension
        native_analysis = None
        analysis_type = None

        # ---- PCAP / PCAPNG DETECTION ----
        if raw_bytes[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4') or file_ext in ('.pcap', '.pcapng'):
            analysis_type = 'pcap'
            native_analysis = _parse_pcap_native(raw_bytes)
        # ---- EVTX DETECTION ----
        elif raw_bytes[:7] == b'ElfFile' or file_ext == '.evtx':
            analysis_type = 'evtx'
            native_analysis = _parse_evtx_native(raw_bytes)
        # ---- TEXT LOG DETECTION ----
        elif file_ext in ('.log', '.txt'):
            analysis_type = 'log'
            native_analysis = _parse_log_native(raw_bytes)
        else:
            # Fallback to OSINT service for other file types
            file_obj.seek(0)
            if hasattr(OSINTService, 'analyze_file'):
                result = OSINTService.analyze_file(file_obj)
            else:
                result = {}

        if native_analysis is not None:
            risk_score = native_analysis.get('risk_score', 0)
            verdict = 'danger' if risk_score > 70 else ('suspicious' if risk_score > 30 else 'clean')
            result = {
                'file_name': file_name,
                'file_size': file_size_str,
                'sha256': sha256_hash,
                'verdict': verdict,
                'risk_score': risk_score,
                'file_type': native_analysis.get('file_type', 'Binary'),
                'analysis_type': analysis_type,
                'native_data': native_analysis,
                'malicious_count': native_analysis.get('malicious_count', 0),
                'suspicious_count': native_analysis.get('suspicious_count', 0),
                'clean_count': 0,
                'total_engines': 1,
            }

        if result:
            scan_record = FileScan.objects.create(
                file_name=result.get('file_name', file_obj.name),
                file_size=result.get('file_size', 'N/A'),
                sha256=result.get('sha256', sha256_hash),
                verdict=result.get('verdict', 'clean'),
                risk_score=result.get('risk_score', 0),
                malicious_count=result.get('malicious_count', 0),
                suspicious_count=result.get('suspicious_count', 0),
                clean_count=result.get('clean_count', 0),
                total_engines=result.get('total_engines', 0),
                file_type=result.get('file_type', 'Generic Binary'),
                user=request.user
            )

            if request.user.profile.is_company_account() and request.user.profile.company:
                scan_record.company = request.user.profile.company
                scan_record.save()

            result['id'] = scan_record.id
            messages.success(request, f"File {file_name} analyzed successfully!")
    elif request.method == "POST":
        messages.error(request, "No file selected.")

    return render(request, 'analyzer/file_checker.html', {'result': result})


def _parse_pcap_native(raw_bytes):
    """Native PCAP parser — reads global + packet headers to compute protocol stats."""
    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    dst_ports = Counter()
    total_packets = 0
    total_data_bytes = 0

    try:
        # Parse global header (24 bytes)
        if len(raw_bytes) < 24:
            return {'file_type': 'PCAP Capture (corrupt)', 'risk_score': 10, 'error': 'File too small'}

        magic = struct.unpack('<I', raw_bytes[:4])[0]
        swapped = magic == 0xa1b2c3d4
        endian = '>' if swapped else '<'

        network = struct.unpack(f'{endian}I', raw_bytes[20:24])[0]
        offset = 24

        while offset + 16 <= len(raw_bytes):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', raw_bytes[offset:offset+16])
            offset += 16

            if incl_len > 65535 or offset + incl_len > len(raw_bytes):
                break

            pkt_data = raw_bytes[offset:offset+incl_len]
            offset += incl_len
            total_packets += 1
            total_data_bytes += orig_len

            # Parse Ethernet + IP header
            if len(pkt_data) >= 34 and network == 1:  # LINKTYPE_ETHERNET
                eth_type = struct.unpack('!H', pkt_data[12:14])[0]
                if eth_type == 0x0800:  # IPv4
                    ip_header = pkt_data[14:]
                    if len(ip_header) >= 20:
                        ihl = (ip_header[0] & 0x0F) * 4
                        protocol_num = ip_header[9]
                        src_ip = '.'.join(str(b) for b in ip_header[12:16])
                        dst_ip = '.'.join(str(b) for b in ip_header[16:20])
                        src_ips[src_ip] += 1
                        dst_ips[dst_ip] += 1

                        if protocol_num == 6:
                            protocols['TCP'] += 1
                            if len(ip_header) >= ihl + 4:
                                dst_port = struct.unpack('!H', ip_header[ihl+2:ihl+4])[0]
                                dst_ports[dst_port] += 1
                        elif protocol_num == 17:
                            protocols['UDP'] += 1
                            if len(ip_header) >= ihl + 4:
                                dst_port = struct.unpack('!H', ip_header[ihl+2:ihl+4])[0]
                                dst_ports[dst_port] += 1
                        elif protocol_num == 1:
                            protocols['ICMP'] += 1
                        else:
                            protocols[f'Proto-{protocol_num}'] += 1
                elif eth_type == 0x0806:
                    protocols['ARP'] += 1
                elif eth_type == 0x86DD:
                    protocols['IPv6'] += 1

        # Risk assessment
        risk_score = 5
        suspicious_ports = {22, 23, 445, 3389, 4444, 5555, 1337, 31337}
        malicious_count = 0
        for port, count in dst_ports.items():
            if port in suspicious_ports:
                risk_score += min(count * 2, 20)
                malicious_count += count
        if total_packets > 10000:
            risk_score += 15
        if len(src_ips) == 1 and len(dst_ports) > 50:
            risk_score += 30  # port scan pattern
            malicious_count += len(dst_ports)
        risk_score = min(risk_score, 100)

        return {
            'file_type': 'PCAP Network Capture',
            'risk_score': risk_score,
            'total_packets': total_packets,
            'total_data_bytes': total_data_bytes,
            'protocols': dict(protocols.most_common(10)),
            'top_src_ips': dict(src_ips.most_common(10)),
            'top_dst_ips': dict(dst_ips.most_common(10)),
            'top_dst_ports': dict(dst_ports.most_common(15)),
            'malicious_count': malicious_count,
            'suspicious_count': len([p for p in dst_ports if p in suspicious_ports]),
        }
    except Exception as e:
        return {'file_type': 'PCAP Capture', 'risk_score': 10, 'error': str(e), 'total_packets': total_packets, 'protocols': dict(protocols)}


def _parse_evtx_native(raw_bytes):
    """Native EVTX parser — scans for security event IDs in XML-like Unicode nodes."""
    events = []
    event_id_counts = Counter()
    security_alerts = []

    SECURITY_EVENT_MAP = {
        '4624': ('Successful Logon', 'info'),
        '4625': ('Failed Logon Attempt', 'warning'),
        '4634': ('Account Logoff', 'info'),
        '4648': ('Logon Using Explicit Credentials', 'warning'),
        '4672': ('Special Privileges Assigned', 'info'),
        '4688': ('New Process Created', 'info'),
        '4697': ('Service Installed', 'warning'),
        '4698': ('Scheduled Task Created', 'warning'),
        '4720': ('User Account Created', 'critical'),
        '4722': ('User Account Enabled', 'warning'),
        '4724': ('Password Reset Attempt', 'warning'),
        '4728': ('Member Added to Security Group', 'critical'),
        '4732': ('Member Added to Local Group', 'warning'),
        '4735': ('Local Group Changed', 'warning'),
        '4740': ('Account Lockout', 'warning'),
        '4756': ('Member Added to Universal Group', 'critical'),
        '4768': ('Kerberos TGT Requested', 'info'),
        '4769': ('Kerberos Service Ticket Requested', 'info'),
        '4771': ('Kerberos Pre-Auth Failed', 'warning'),
        '4776': ('NTLM Authentication Attempt', 'info'),
        '7045': ('New Service Installed', 'critical'),
        '1102': ('Audit Log Cleared', 'critical'),
    }

    try:
        # Decode bytes attempting UTF-16LE (typical for EVTX XML fragments)
        text_content = ''
        try:
            text_content = raw_bytes.decode('utf-16-le', errors='ignore')
        except Exception:
            text_content = raw_bytes.decode('utf-8', errors='ignore')

        # Find EventID patterns in XML fragments
        event_id_pattern = re.compile(r'EventID[^>]*>\s*(\d{1,5})\s*<', re.IGNORECASE)
        time_pattern = re.compile(r'TimeCreated[^>]*SystemTime=["\']([^"\']+)["\']', re.IGNORECASE)
        computer_pattern = re.compile(r'Computer[^>]*>\s*([^<]+)\s*<', re.IGNORECASE)

        event_ids_found = event_id_pattern.findall(text_content)
        times_found = time_pattern.findall(text_content)
        computers_found = computer_pattern.findall(text_content)

        computer_name = computers_found[0] if computers_found else 'Unknown'

        for i, eid in enumerate(event_ids_found):
            event_id_counts[eid] += 1
            if eid in SECURITY_EVENT_MAP:
                desc, severity = SECURITY_EVENT_MAP[eid]
                timestamp = times_found[i] if i < len(times_found) else 'N/A'
                security_alerts.append({
                    'event_id': eid,
                    'description': desc,
                    'severity': severity,
                    'timestamp': timestamp[:19].replace('T', ' ') if timestamp != 'N/A' else 'N/A',
                    'computer': computer_name,
                })

        # Risk assessment
        risk_score = 5
        critical_events = sum(1 for a in security_alerts if a['severity'] == 'critical')
        warning_events = sum(1 for a in security_alerts if a['severity'] == 'warning')
        failed_logons = event_id_counts.get('4625', 0)

        risk_score += critical_events * 15
        risk_score += warning_events * 5
        if failed_logons > 10:
            risk_score += 25  # brute force indicator
        if event_id_counts.get('1102', 0) > 0:
            risk_score += 30  # audit log tampering
        risk_score = min(risk_score, 100)

        return {
            'file_type': 'Windows Event Log (EVTX)',
            'risk_score': risk_score,
            'total_events': len(event_ids_found),
            'event_id_distribution': dict(event_id_counts.most_common(15)),
            'security_alerts': security_alerts[:50],
            'computer_name': computer_name,
            'critical_count': critical_events,
            'warning_count': warning_events,
            'failed_logons': failed_logons,
            'malicious_count': critical_events,
            'suspicious_count': warning_events,
        }
    except Exception as e:
        return {'file_type': 'Windows Event Log (EVTX)', 'risk_score': 10, 'error': str(e), 'total_events': 0, 'security_alerts': []}


def _parse_log_native(raw_bytes):
    """Native text log parser — detects HTTP access patterns, SQLi, path traversals, brute-force."""
    try:
        text = raw_bytes.decode('utf-8', errors='ignore')
    except Exception:
        text = raw_bytes.decode('latin-1', errors='ignore')

    lines = text.strip().split('\n')
    total_lines = len(lines)

    # HTTP response code analysis
    http_codes = Counter()
    http_code_pattern = re.compile(r'\s(\d{3})\s')

    # Endpoint analysis
    endpoints = Counter()
    endpoint_pattern = re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"]+)')

    # Threat patterns
    sqli_patterns = re.compile(r"(?:union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table|select\s+.*\s+from\s+|insert\s+into|update\s+.*\s+set|delete\s+from|exec\s*\(|xp_cmdshell|benchmark\s*\(|sleep\s*\()", re.IGNORECASE)
    path_traversal_pattern = re.compile(r'(?:\.\.[\\/]|%2e%2e[\\/]|%252e%252e)', re.IGNORECASE)
    xss_pattern = re.compile(r'(?:<script|javascript:|onerror\s*=|onload\s*=|eval\s*\(|alert\s*\()', re.IGNORECASE)
    brute_force_pattern = re.compile(r'(?:Failed\s+password|authentication\s+failure|invalid\s+(?:user|password)|login\s+failed|access\s+denied)', re.IGNORECASE)
    rce_pattern = re.compile(r'(?:;\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby)|\|\s*(?:cat|ls|id|whoami))', re.IGNORECASE)

    sqli_hits = []
    path_traversal_hits = []
    xss_hits = []
    brute_force_hits = []
    rce_hits = []
    src_ips = Counter()
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for i, line in enumerate(lines):
        # Extract IPs
        ip_match = ip_pattern.search(line)
        if ip_match:
            src_ips[ip_match.group(1)] += 1

        # HTTP codes
        code_match = http_code_pattern.search(line)
        if code_match:
            code = code_match.group(1)
            if code.startswith(('1', '2', '3', '4', '5')):
                http_codes[code] += 1

        # Endpoints
        ep_match = endpoint_pattern.search(line)
        if ep_match:
            endpoints[ep_match.group(1)] += 1

        # Threat detection
        if sqli_patterns.search(line):
            sqli_hits.append({'line': i + 1, 'content': line[:200].strip()})
        if path_traversal_pattern.search(line):
            path_traversal_hits.append({'line': i + 1, 'content': line[:200].strip()})
        if xss_pattern.search(line):
            xss_hits.append({'line': i + 1, 'content': line[:200].strip()})
        if brute_force_pattern.search(line):
            brute_force_hits.append({'line': i + 1, 'content': line[:200].strip()})
        if rce_pattern.search(line):
            rce_hits.append({'line': i + 1, 'content': line[:200].strip()})

    # Risk assessment
    risk_score = 0
    malicious_count = 0
    suspicious_count = 0

    if sqli_hits:
        risk_score += min(len(sqli_hits) * 8, 35)
        malicious_count += len(sqli_hits)
    if path_traversal_hits:
        risk_score += min(len(path_traversal_hits) * 6, 25)
        malicious_count += len(path_traversal_hits)
    if xss_hits:
        risk_score += min(len(xss_hits) * 5, 20)
        suspicious_count += len(xss_hits)
    if brute_force_hits:
        risk_score += min(len(brute_force_hits) * 3, 30)
        suspicious_count += len(brute_force_hits)
    if rce_hits:
        risk_score += min(len(rce_hits) * 10, 40)
        malicious_count += len(rce_hits)
    if http_codes.get('403', 0) > 50:
        risk_score += 10
    if http_codes.get('500', 0) > 20:
        risk_score += 10
    risk_score = min(risk_score, 100)

    return {
        'file_type': 'Text / Server Log',
        'risk_score': risk_score,
        'total_lines': total_lines,
        'http_codes': dict(http_codes.most_common(10)),
        'top_endpoints': dict(endpoints.most_common(15)),
        'top_src_ips': dict(src_ips.most_common(10)),
        'sqli_hits': sqli_hits[:20],
        'path_traversal_hits': path_traversal_hits[:20],
        'xss_hits': xss_hits[:20],
        'brute_force_hits': brute_force_hits[:20],
        'rce_hits': rce_hits[:20],
        'malicious_count': malicious_count,
        'suspicious_count': suspicious_count,
        'threat_summary': {
            'SQLi Attempts': len(sqli_hits),
            'Path Traversals': len(path_traversal_hits),
            'XSS Attempts': len(xss_hits),
            'Brute Force': len(brute_force_hits),
            'RCE Attempts': len(rce_hits),
        }
    }


# =====================================================================
# 🔏 BLACKLIST CHECKER
# =====================================================================
def blacklist_checker(request):
    query_result = None
    
    # 1. Traitement dial "Ajouter un blocage"
    if request.method == "POST" and "add_local" in request.POST:
        ip_to_block = request.POST.get('ip_address', '').strip()
        if ip_to_block:
            BlacklistedIP.objects.get_or_create(
                ip_address=ip_to_block,
                defaults={'reason': request.POST.get('reason', 'Manual Block'), 'added_by': request.user}
            )
            messages.success(request, f"✅ IP {ip_to_block} blocked.")
            
    # 2. Traitement dial "Check Blacklist" (QUERY_LEDGER)
    elif request.method == "POST" and "query_ledger" in request.POST:
        target = request.POST.get('target', '').strip()
        if target:
            # Hna k-t-3yet l-service li 3ndk
            query_result = OSINTService.check_blacklist(target) if hasattr(OSINTService, 'check_blacklist') else {}
            # N-zidou l-IP l-resultat bach t-ban f template
            query_result['target'] = target 
            query_result['verdict'] = 'danger' if query_result.get('risk_score', 0) > 50 else 'clean'
            query_result['source'] = 'ABUSEIPDB'
    
    # 3. Récupération dial l-ledger local
    local_ledger = BlacklistedIP.objects.all().order_by('-added_at')
    
    context = {
        'result': query_result, # Had l-var hiya li kat-ban f template
        'local_ledger': local_ledger
    }
    return render(request, 'analyzer/blacklist.html', context)


# =====================================================================
# 🎛️ SERVER INTELLIGENCE
# =====================================================================
@login_required
def server_intel(request):
    try:
        cyber_news = OSINTService.get_cyber_warfare_news()
    except Exception:
        cyber_news = []

    return render(request, 'analyzer/server_intel.html', {'cyber_news': cyber_news})


# =====================================================================
# 📬 CONTACT & SUPPORT
# =====================================================================

@login_required
def contact_view(request):
    """Support page"""
    return render(request, 'analyzer/contact.html')


# =====================================================================
# 💻 TACTICAL NETWORK TERMINAL
# =====================================================================
@login_required
def terminal_view(request):
    """MobaXterm-style remote CLI console view for network architecture devices"""
    hosts = [
        {"id": "CORE-ROUTER-01", "name": "CORE-ROUTER-01", "ip": "10.0.0.1", "type": "router", "status": "online"},
        {"id": "FIREWALL-01", "name": "FIREWALL-01", "ip": "192.168.1.254", "type": "firewall", "status": "warning"},
        {"id": "LOAD-BALANCER", "name": "LOAD-BALANCER", "ip": "192.168.1.253", "type": "balancer", "status": "online"},
        {"id": "DIST-SW-01", "name": "DIST-SW-01", "ip": "192.168.1.2", "type": "switch", "status": "online"},
        {"id": "DIST-SW-02", "name": "DIST-SW-02", "ip": "192.168.1.3", "type": "switch", "status": "online"},
        {"id": "ACC-SW-01", "name": "ACC-SW-01", "ip": "192.168.1.10", "type": "switch", "status": "online"},
        {"id": "ACC-SW-02", "name": "ACC-SW-02", "ip": "192.168.1.11", "type": "switch", "status": "online"},
        {"id": "SRV-SW-01", "name": "SRV-SW-01", "ip": "192.168.1.12", "type": "switch", "status": "online"},
        {"id": "WEB-SRV", "name": "WEB-SRV", "ip": "192.168.1.100", "type": "server", "status": "critical"},
        {"id": "DB-SRV", "name": "DB-SRV", "ip": "192.168.1.101", "type": "server", "status": "online"},
        {"id": "STORAGE", "name": "STORAGE", "ip": "192.168.1.102", "type": "server", "status": "online"},
    ]
    
    context = {
        'hosts': hosts,
        'terminal_title': 'CYBEROPS // REMOTE CONSOLE TERMINAL'
    }
    return render(request, 'analyzer/terminal.html', context)


# =====================================================================
# 🪤 HONEYPOT NETWORK MODULE
# =====================================================================
@login_required
def honeypot_view(request):
    """Honeypot overview page displaying logs and automatic blacklist captures"""
    # Seed default ports if none exist
    if not HoneypotPort.objects.exists():
        default_ports = [
            (22, "SSH"),
            (80, "HTTP/Web Admin"),
            (3306, "MySQL Database"),
            (8080, "Tomcat Proxy"),
        ]
        for p, s in default_ports:
            HoneypotPort.objects.create(port=p, service_name=s, is_active=True)

    honeypot_blacklisted = BlacklistedIP.objects.filter(
        reason__icontains='Honeypot'
    ).order_by('-added_at')

    # Fetch listeners from database
    db_ports = HoneypotPort.objects.all().order_by('port')
    listeners = []
    for dp in db_ports:
        hits = HoneypotLog.objects.filter(port=dp.port).count()
        listeners.append({
            "id": dp.id,
            "port": dp.port,
            "service": dp.service_name,
            "status": "LISTEN" if dp.is_active else "DISABLED",
            "hits": hits,
            "is_active": dp.is_active
        })

    # Fetch recent logs from database
    honeypot_logs = HoneypotLog.objects.all().order_by('-timestamp')[:50]

    context = {
        'honeypot_blacklisted': honeypot_blacklisted,
        'listeners': listeners,
        'honeypot_logs': honeypot_logs,
    }
    return render(request, 'analyzer/honeypot.html', context)


@csrf_exempt
def honeypot_probe(request):
    """API endpoint to capture malicious requests and auto-blacklist the IP"""
    simulated_ip = request.GET.get('ip')
    port_num = request.GET.get('port', 22)
    service_name = request.GET.get('service', 'SSH')
    reason = request.GET.get('reason', 'Intrusion Attempt // Honeypot Trigger')
    payload = request.GET.get('payload', '')

    try:
        port_num = int(port_num)
    except ValueError:
        port_num = 22

    if simulated_ip:
        ip = simulated_ip.strip()
    else:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '').strip()
            
    if not ip or ip == '::1':
        ip = '127.0.0.1'

    # Save to HoneypotLog
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    HoneypotLog.objects.create(
        ip_address=ip,
        port=port_num,
        service_name=service_name,
        user_agent=user_agent,
        payload=payload
    )
    
    # Register in blacklist database
    created = False
    try:
        blacklisted_obj, created = BlacklistedIP.objects.get_or_create(
            ip_address=ip,
            defaults={
                'reason': f"Honeypot Intrusion (Port {port_num} - {service_name}): {reason}",
                'added_by': request.user if request.user.is_authenticated else None
            }
        )
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
        
    return JsonResponse({
        "status": "CAPTURED",
        "ip_address": ip,
        "reason": reason,
        "newly_added": created,
        "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_id": blacklisted_obj.id
    })


@login_required
def honeypot_release(request):
    """API endpoint to release an IP from the blacklist database"""
    ip_id = request.GET.get('id')
    if ip_id:
        try:
            ip_obj = get_object_or_404(BlacklistedIP, id=ip_id)
            ip_address = ip_obj.ip_address
            ip_obj.delete()
            return JsonResponse({"status": "RELEASED", "ip_address": ip_address})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "No ID provided"}, status=400)


@login_required
def check_threat_status(request):
    """API endpoint to check current threat level based on recent honeypot logs and high risk scans"""
    fifteen_mins_ago = timezone.now() - datetime.timedelta(minutes=15)
    recent_honeypots = HoneypotLog.objects.filter(timestamp__gte=fifteen_mins_ago)
    if recent_honeypots.exists():
        latest = recent_honeypots.order_by('-timestamp').first()
        return JsonResponse({
            "status": "CRITICAL",
            "message": f"CRITICAL: Intrusion attempt from {latest.ip_address} on port {latest.port} ({latest.service_name})!",
            "timestamp": latest.timestamp.strftime("%H:%M:%S")
        })

    five_mins_ago = timezone.now() - datetime.timedelta(minutes=5)
    recent_ip_risks = IPScan.objects.filter(created_at__gte=five_mins_ago, risk_score__gt=80)
    recent_url_risks = URLScan.objects.filter(created_at__gte=five_mins_ago, risk_score__gt=80)
    recent_file_risks = FileScan.objects.filter(created_at__gte=five_mins_ago, risk_score__gt=80)

    if recent_ip_risks.exists():
        latest = recent_ip_risks.order_by('-created_at').first()
        return JsonResponse({
            "status": "WARNING",
            "message": f"WARNING: High risk IP detected: {latest.ip} (Risk Score: {latest.risk_score}%)!",
            "timestamp": latest.created_at.strftime("%H:%M:%S")
        })
    elif recent_url_risks.exists():
        latest = recent_url_risks.order_by('-created_at').first()
        return JsonResponse({
            "status": "WARNING",
            "message": f"WARNING: High risk URL detected: {latest.url[:30]}... (Risk Score: {latest.risk_score}%)!",
            "timestamp": latest.created_at.strftime("%H:%M:%S")
        })
    elif recent_file_risks.exists():
        latest = recent_file_risks.order_by('-created_at').first()
        return JsonResponse({
            "status": "WARNING",
            "message": f"WARNING: High risk file detected: {latest.file_name} (Risk Score: {latest.risk_score}%)!",
            "timestamp": latest.created_at.strftime("%H:%M:%S")
        })

    return JsonResponse({"status": "NORMAL", "message": "All systems operational.", "timestamp": timezone.now().strftime("%H:%M:%S")})


@login_required
def blacklist_edit(request, ip_id):
    """Edit the reason description for a blacklisted IP"""
    if request.method == "POST":
        ip_obj = get_object_or_404(BlacklistedIP, id=ip_id)
        new_reason = request.POST.get('reason', '').strip()
        if new_reason:
            ip_obj.reason = new_reason
            ip_obj.save()
            messages.success(request, f"Updated block reason for IP {ip_obj.ip_address} successfully.")
        else:
            messages.error(request, "Reason cannot be empty.")
    return redirect('analyzer:blacklist_checker')


@login_required
def blacklist_delete(request, ip_id):
    """Delete an IP from the blacklist"""
    if request.method == "POST" or request.method == "GET":
        ip_obj = get_object_or_404(BlacklistedIP, id=ip_id)
        ip_address = ip_obj.ip_address
        ip_obj.delete()
        messages.info(request, f"Removed IP {ip_address} from the blacklist.")
    return redirect('analyzer:blacklist_checker')


@login_required
def honeypot_add_port(request):
    """Add a new honeypot port listener configuration"""
    if request.method == "POST":
        port_num = request.POST.get('port')
        service = request.POST.get('service_name', '').strip()
        if port_num and service:
            try:
                port_num = int(port_num)
                if port_num < 1 or port_num > 65535:
                    messages.error(request, "Port number must be between 1 and 65535.")
                else:
                    HoneypotPort.objects.create(port=port_num, service_name=service, is_active=True)
                    messages.success(request, f"Honeypot listener registered on Port {port_num} ({service}).")
            except ValueError:
                messages.error(request, "Invalid port number.")
            except Exception as e:
                messages.error(request, f"Error: Port might already be configured or: {str(e)}")
    return redirect('analyzer:honeypot')


@login_required
def honeypot_toggle_port(request, port_id):
    """Toggle the active state of a honeypot port listener"""
    port_obj = get_object_or_404(HoneypotPort, id=port_id)
    port_obj.is_active = not port_obj.is_active
    port_obj.save()
    status_str = "ENABLED" if port_obj.is_active else "DISABLED"
    messages.info(request, f"Port {port_obj.port} ({port_obj.service_name}) has been {status_str}.")
    return redirect('analyzer:honeypot')


@login_required
def honeypot_remove_port(request, port_id):
    """Delete a honeypot port listener configuration"""
    port_obj = get_object_or_404(HoneypotPort, id=port_id)
    port = port_obj.port
    service = port_obj.service_name
    port_obj.delete()
    messages.warning(request, f"Removed honeypot listener on Port {port} ({service}).")
    return redirect('analyzer:honeypot')


# =====================================================================
# 🔬 DEEP FORENSIC LOG & PACKET ANALYZER
# =====================================================================
@login_required
def deep_analyzer(request):
    """Deep forensic analyzer for .log, .pcap, .pcapng, .evtx files"""
    result = None
    if request.method == "POST" and request.FILES.get('forensic_file'):
        file_obj = request.FILES['forensic_file']
        file_name = file_obj.name
        file_ext = os.path.splitext(file_name)[1].lower()

        # Validate extension
        allowed_extensions = ('.log', '.txt', '.pcap', '.pcapng', '.evtx')
        if file_ext not in allowed_extensions:
            messages.error(request, f"Unsupported file type '{file_ext}'. Accepted: {', '.join(allowed_extensions)}")
            return render(request, 'analyzer/deep_analyzer.html', {'result': None})

        raw_bytes = file_obj.read()
        result = DeepForensicAnalyzer.analyze_forensics(file_name, raw_bytes)

        # Save scan record to database
        try:
            scan_record = FileScan.objects.create(
                file_name=result.get('file_name', file_name),
                file_size=result.get('file_size', 'N/A'),
                sha256=result.get('sha256', ''),
                verdict=result.get('verdict', 'clean'),
                risk_score=result.get('risk_score', 0),
                malicious_count=result.get('malicious_count', 0),
                suspicious_count=result.get('suspicious_count', 0),
                clean_count=0,
                total_engines=1,
                file_type=result.get('file_type', 'Forensic Analysis'),
                user=request.user
            )
            if request.user.profile.is_company_account() and request.user.profile.company:
                scan_record.company = request.user.profile.company
                scan_record.save()
            result['id'] = scan_record.id
        except Exception as e:
            print(f"[DEEP_ANALYZER] DB save error: {e}")

        messages.success(request, f"Deep forensic analysis of '{file_name}' complete!")

    elif request.method == "POST":
        messages.error(request, "No file selected for analysis.")

    return render(request, 'analyzer/deep_analyzer.html', {'result': result})