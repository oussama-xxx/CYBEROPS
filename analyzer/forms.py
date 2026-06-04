from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordChangeForm
from .models import UserProfile, Company, BlacklistedIP

# =====================================================================
# 🔐 AUTHENTICATION FORMS
# =====================================================================

class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'you@example.com'}))
    
    # Corporate Node Infrastructure
    company_name = forms.CharField(max_length=200, required=True, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Cyber Security Corp'}))
    registration_number = forms.CharField(max_length=100, required=False, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'ICE / RC / Tax ID'}))
    company_phone = forms.CharField(max_length=20, required=False, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': '+212 522-XXXXXX'}))
    website = forms.URLField(required=False, widget=forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://www.company.ma'}))
    address = forms.CharField(required=False, widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 2, 'placeholder': 'Full corporate address'}))
    city = forms.CharField(max_length=100, required=False, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Casablanca'}))
    country = forms.ChoiceField(choices=[('Morocco', 'Morocco'), ('Other', 'Other')], initial='Morocco', widget=forms.Select(attrs={'class': 'form-control'}))
    plan = forms.ChoiceField(
        choices=[
            ('free', 'FREE - 100 scans/month (Basic Engine)'),
            ('basic', 'BASIC - 500 scans/month (50 $/month)'),
            ('professional', 'PROFESSIONAL - 5,000 scans/month (200 $/month)'),
            ('enterprise', 'ENTERPRISE - Unlimited Allocation (500 $/month)')
        ],
        initial='free',
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'class': 'form-control', 'placeholder': 'Choose a username'})
        self.fields['password1'].widget.attrs.update({'class': 'form-control', 'placeholder': 'Enter password'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control', 'placeholder': 'Confirm password'})
        self.fields['username'].help_text = None
        self.fields['password1'].help_text = 'Must contain at least 8 characters.'
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Email already registered.')
        return email
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('Username already taken.')
        return username

    def clean_company_name(self):
        company_name = self.cleaned_data.get('company_name')
        if Company.objects.filter(name=company_name).exists():
            raise forms.ValidationError('A company with this name is already registered.')
        return company_name
    
    def clean(self):
        cleaned_data = super().clean()
        return cleaned_data


class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))
    remember_me = forms.BooleanField(required=False, initial=False, widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}))
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['remember_me'].label = "Remember me"


class CustomPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Current password'}))
    new_password1 = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'New password'}))
    new_password2 = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm new password'}))
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['new_password1'].help_text = 'Must contain at least 8 characters.'


# =====================================================================
# 👤 USER PROFILE FORMS
# =====================================================================

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['first_name', 'last_name', 'phone_number', 'establishment', 'sector', 'email_notifications', 'language', 'theme']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First name'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last name'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '+212 XXX XXX XXX'}),
            'establishment': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'School/University/Company'}),
            'sector': forms.Select(attrs={'class': 'form-control'}),
            'email_notifications': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'language': forms.Select(attrs={'class': 'form-control'}, choices=[('en', 'English'), ('fr', 'Français'), ('ar', 'العربية')]),
            'theme': forms.Select(attrs={'class': 'form-control'}, choices=[('dark', 'Dark Theme'), ('light', 'Light Theme'), ('cyber', 'Cyber Theme')]),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['first_name'].required = False
        self.fields['last_name'].required = False
        self.fields['phone_number'].required = False
        self.fields['establishment'].required = False
        self.fields['sector'].required = False
        self.fields['language'].required = False
        self.fields['theme'].required = False


class UserUpdateForm(forms.ModelForm):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email address'}))
    
    class Meta:
        model = User
        fields = ['username', 'email']
        widgets = {'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'})}
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.exclude(pk=self.instance.pk).filter(email=email).exists():
            raise forms.ValidationError('Email already in use.')
        return email
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.exclude(pk=self.instance.pk).filter(username=username).exists():
            raise forms.ValidationError('Username already taken.')
        return username


# =====================================================================
# 🏢 COMPANY FORMS
# =====================================================================

class CompanyRegistrationForm(forms.ModelForm):
    confirm_email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Confirm email'}))
    
    class Meta:
        model = Company
        fields = ['name', 'registration_number', 'email', 'phone', 'website', 'address', 'city', 'country', 'establishment_type', 'plan', 'logo']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Company name'}),
            'registration_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'ICE / RC / Tax ID'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'company@example.com'}),
            'phone': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '+212 XXX XXX XXX'}),
            'website': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://example.com'}),
            'address': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Full address'}),
            'city': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'City'}),
            'country': forms.Select(attrs={'class': 'form-control'}),
            'establishment_type': forms.Select(attrs={'class': 'form-control'}),
            'plan': forms.Select(attrs={'class': 'form-control'}),
            'logo': forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['country'].choices = [('Morocco', 'Morocco'), ('Algeria', 'Algeria'), ('Tunisia', 'Tunisia'), ('France', 'France'), ('Spain', 'Spain'), ('Other', 'Other')]
    
    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        confirm_email = cleaned_data.get('confirm_email')
        if email and confirm_email and email != confirm_email:
            self.add_error('confirm_email', 'Email addresses do not match.')
        if Company.objects.filter(email=email).exists():
            self.add_error('email', 'Company already registered with this email.')
        return cleaned_data


class CompanySettingsForm(forms.ModelForm):
    class Meta:
        model = Company
        fields = ['name', 'phone', 'website', 'address', 'city', 'country', 'establishment_type', 'logo', 'notes']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'website': forms.URLInput(attrs={'class': 'form-control'}),
            'address': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'city': forms.TextInput(attrs={'class': 'form-control'}),
            'country': forms.Select(attrs={'class': 'form-control'}),
            'establishment_type': forms.Select(attrs={'class': 'form-control'}),
            'logo': forms.FileInput(attrs={'class': 'form-control'}),
            'notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
        }


class CompanyUserForm(forms.Form):
    username = forms.CharField(max_length=150, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email address'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm password'}))
    user_type = forms.ChoiceField(choices=[('company_member', 'Standard Member'), ('company_admin', 'Administrator')], widget=forms.Select(attrs={'class': 'form-control'}), initial='company_member')
    
    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get('password') != cleaned_data.get('confirm_password'):
            self.add_error('confirm_password', 'Passwords do not match.')
        return cleaned_data
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('Username already taken.')
        return username
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Email already registered.')
        return email