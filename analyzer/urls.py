from django.urls import path
from . import views
from . import company_views

app_name = 'analyzer'

urlpatterns = [
    # Authentication URLs
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/settings/', views.profile_settings_view, name='profile_settings'),
    
    # Company URLs (Deprecated/Bypassed)
    # path('company/register/', company_views.register_company, name='register_company'),
    # path('company/dashboard/', company_views.company_dashboard, name='company_dashboard'),
    # path('company/settings/', company_views.company_settings, name='company_settings'),
    # path('company/team/', company_views.manage_team, name='manage_team'),
    # path('company/billing/', company_views.company_billing, name='company_billing'),
    # path('company/analytics/', company_views.company_analytics, name='company_analytics'),
    
    # Main Application URLs
    path('', views.home, name='home'),  # views.home machi views.home_view
    path('ip/', views.ip_analyzer, name='ip_analyzer'),
    path('url/', views.url_analyzer, name='url_analyzer'),
    path('file/', views.file_analyzer, name='file_analyzer'),
    path('blacklist/', views.blacklist_checker, name='blacklist_checker'),
    path('server/', views.server_intel, name='server_intel'),
    path('contact/', views.contact_view, name='contact'),
    path('supervisor/', views.supervisor, name='supervisor'),
    path('chatbot/', views.chatbot, name='chatbot'),
    path('chatbot/api/', views.chatbot_api, name='chatbot_api'),
    path('terminal/', views.terminal_view, name='terminal'),
    path('honeypot/', views.honeypot_view, name='honeypot'),
    path('honeypot/probe/', views.honeypot_probe, name='honeypot_probe'),
    path('honeypot/release/', views.honeypot_release, name='honeypot_release'),
    path('check_threat/', views.check_threat_status, name='check_threat_status'),
    path('blacklist/edit/<int:ip_id>/', views.blacklist_edit, name='blacklist_edit'),
    path('blacklist/delete/<int:ip_id>/', views.blacklist_delete, name='blacklist_delete'),
    path('honeypot/port/add/', views.honeypot_add_port, name='honeypot_add_port'),
    path('honeypot/port/toggle/<int:port_id>/', views.honeypot_toggle_port, name='honeypot_toggle_port'),
    path('honeypot/port/delete/<int:port_id>/', views.honeypot_remove_port, name='honeypot_remove_port'),
    path('deep_analyzer/', views.deep_analyzer, name='deep_analyzer'),
]