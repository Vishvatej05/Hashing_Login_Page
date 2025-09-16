from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_protect
from .models import LoginFingerprint, generate_fingerprint
from django.contrib.admin.views.decorators import staff_member_required
from django.core import signing
from django.core.mail import send_mail
import re


@csrf_protect
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        email = request.POST.get('email', '').strip()

        # Basic validations
        if not username:
            messages.error(request, 'Username is required.')
            return render(request, 'accounts/register.html')
        if not password or len(password) < 6:
            messages.error(request, 'Password is required (min 6 chars).')
            return render(request, 'accounts/register.html')
        if not email or not re.fullmatch(r'^[\w.+-]+@gmail\.com$', email, flags=re.IGNORECASE):
            messages.error(request, 'A valid Gmail address is required.')
            return render(request, 'accounts/register.html')
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return render(request, 'accounts/register.html')
        if User.objects.filter(email__iexact=email).exists():
            messages.error(request, 'Email is already registered.')
            return render(request, 'accounts/register.html')

        user = User.objects.create_user(username=username, password=password, email=email, is_active=False)
        # Save fingerprint of username:password
        try:
            LoginFingerprint.objects.create(
                user=user,
                fingerprint=generate_fingerprint(username, password),
            )
        except Exception:
            # If fingerprint collides or fails, still allow registration but warn.
            messages.warning(request, 'Registered, but fingerprint save failed.')
        # Send verification email with signed token
        token = signing.dumps({'u': user.pk})
        verify_url = request.build_absolute_uri(f"/verify/{token}/")
        send_mail(
            subject='Verify your account',
            message=f'Click to verify your account: {verify_url}',
            from_email=None,
            recipient_list=[email],
        )
        messages.success(request, 'Registration successful. Check your Gmail for a verification link.')
        return redirect('login')
    return render(request, 'accounts/register.html')


@csrf_protect
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        # Verify fingerprint first
        fp = generate_fingerprint(username, password)
        try:
            stored = LoginFingerprint.objects.select_related('user').get(user__username=username)
            if stored.fingerprint != fp:
                messages.error(request, 'Hash fingerprint mismatch.')
                return render(request, 'accounts/login.html')
        except LoginFingerprint.DoesNotExist:
            messages.error(request, 'No fingerprint stored for this user.')
            return render(request, 'accounts/login.html')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            if not user.is_active:
                messages.error(request, 'Account not verified. Check your Gmail inbox.')
                return render(request, 'accounts/login.html')
            login(request, user)
            return redirect('profile')
        messages.error(request, 'Invalid credentials.')
    return render(request, 'accounts/login.html')


@login_required
def profile(request):
    return render(request, 'accounts/profile.html')


def logout_view(request):
    logout(request)
    return redirect('login')

@staff_member_required
def accounts_table(request):
    users = (
        User.objects.select_related('login_fingerprint')
        .all()
        .order_by('username')
    )
    rows = []
    for u in users:
        lf = getattr(u, 'login_fingerprint', None)
        rows.append({
            'username': u.username,
            'fingerprint': lf.fingerprint if lf else '',
        })
    return render(request, 'accounts/accounts_table.html', {'rows': rows})


@csrf_protect
def verify(request, token: str):
    try:
        data = signing.loads(token, max_age=60 * 60 * 24)
        user = User.objects.get(pk=data['u'])
        user.is_active = True
        user.save(update_fields=['is_active'])
        messages.success(request, 'Your email is verified. You can now log in.')
    except Exception:
        messages.error(request, 'Invalid or expired verification link.')
    return redirect('login')


@csrf_protect
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        if not email:
            messages.error(request, 'Email is required.')
            return render(request, 'accounts/forgot_password.html')
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            # Do not reveal whether the email exists
            messages.success(request, 'If the email exists, a reset link was sent.')
            return redirect('login')
        token = signing.dumps({'u': user.pk})
        reset_url = request.build_absolute_uri(f"/reset/{token}/")
        send_mail(
            subject='Reset your password',
            message=f'Click to reset your password: {reset_url}',
            from_email=None,
            recipient_list=[email],
        )
        messages.success(request, 'If the email exists, a reset link was sent.')
        return redirect('login')
    return render(request, 'accounts/forgot_password.html')


@csrf_protect
def reset_password(request, token: str):
    try:
        data = signing.loads(token, max_age=60 * 60 * 24)
        user = User.objects.get(pk=data['u'])
    except Exception:
        messages.error(request, 'Invalid or expired reset link.')
        return redirect('login')

    if request.method == 'POST':
        password = request.POST.get('password', '')
        if not password or len(password) < 6:
            messages.error(request, 'Password must be at least 6 characters.')
            return render(request, 'accounts/reset_password.html', {'token': token})
        user.set_password(password)
        user.is_active = True
        user.save(update_fields=['password', 'is_active'])
        # Refresh fingerprint
        fp_value = generate_fingerprint(user.username, password)
        LoginFingerprint.objects.update_or_create(user=user, defaults={'fingerprint': fp_value})
        messages.success(request, 'Password updated. You can now log in.')
        return redirect('login')

    return render(request, 'accounts/reset_password.html', {'token': token})
