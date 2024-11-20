from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.core.mail import EmailMultiAlternatives
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import default_token_generator
from .models import Profile, User
from django.conf import settings

# Create your views here.

def home(request):
    return render(request, 'app1/home.html')


def register(request):
    """A function to handle the user registration, save the username, email, and password in the database"""
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Check if passwords match
        if password != confirm_password:
            return render(request, 'app1/register.html', {'error': 'Passwords do not match.'})

        # Check if the username already exists
        if User.objects.filter(username=username).exists():
            return render(request, 'app1/register.html', {'error': 'Username already exists. Please choose a different username.'})

        # Check if a user with the given email already exists
        if User.objects.filter(email=email).exists():
            return render(request, 'app1/register.html', {'error': 'User with this email already exists. Please register with a different email.'})

        # Create a new user with username, email, and password, then save to the database
        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()

        # Display success message
        messages.success(request, 'Registration successful!')

        # Authenticate and log in the user, then redirect to the home page
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')

    return render(request, 'app1/register.html')



def login_user(request):
    """A function to handle the user login, check the credentials from the database, and render the Athena chat HTML."""
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('pwd')

        # Check if a user exists with the provided email
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'Invalid email or password.')
            return render(request, 'app1/login.html')

        # Authenticate using the username from the email and the provided password
        user = authenticate(request, username=user.username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Invalid email or password.')

    return render(request, 'app1/login.html')


def logout_user(request):
    """Function to handle the logout"""
    logout(request)
    return render(request, 'app1/home.html')


def password_reset_request(request):
    """Function to handle password reset request and send the password reset link to mail id"""
    # Check if request method was post and get the email from html form
    if request.method == 'POST':
        email = request.POST.get('email')
        users = User.objects.filter(email=email)
        # checks if there are any users in the database with the provided email address
        if users.exists():
            # A password reset token is generated using Django default_token_generator and new token will be saved in Profile
            for user in users:
                token = default_token_generator.make_token(user)
                profile, created = Profile.objects.get_or_create(user=user)
                profile.reset_token = token
                profile.save()
                # A password reset link is constructed using the user's encoded primary key and the token and send to email using reverse
                uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                reset_link = request.build_absolute_uri(
                    reverse('password_reset_confirm', kwargs={
                            'uidb64': uidb64, 'token': token})
                )
                # An email subject and message are prepared, an email is created and sent to the user containing the reset link.
                mail_subject = 'Reset your password'
                message = (
                    f'Hi {user.username},\n\n'
                    f'You are receiving this email because you requested a password reset for your account.\n\n'
                    f'Please click the link below to reset your password:\n\n'
                    f'{reset_link}\n\n'
                    f'If you did not request this, please ignore this email.\n\n'
                    f'Thanks,\nThe Support Team'
                )

                email = EmailMultiAlternatives(
                    mail_subject, message, settings.EMAIL_HOST_USER, [email])
                email.content_subtype = 'plain'
                email.send()
            # Redirected to html page which saying password rest was done and check for mail
            return redirect('password_reset_done')
        else:
            # To display error message if user was not found
            messages.error(request, 'No user found with that email address.')
            return render(request, 'app1/reset.html')

    return render(request, 'app1/reset.html')


def password_reset_confirm(request, uidb64, token):
    """The function confirms the password reset request by validating the reset token and the user, allowing the user to set a new password."""
    # Decodes the base64-encoded user ID and retrieve the user with that ID
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    # Checks if user in not empty and the provided token is valid for the user.
    if user is not None and default_token_generator.check_token(user, token):
        # Check if request method was post and get the new_password and confirm_password from html form and save that in db if both are same
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                # Then reset the token value to empty string and saves the updated Profile object.
                profile = Profile.objects.get(user=user)
                profile.reset_token = ''
                profile.save()
                # Display success message if Passwords reset was successful
                messages.success(
                    request, 'Your password has been reset successfully. You can now login with your new password.')
                return redirect('login') # Redirect to login page after successful reset
            else:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'app1/reset_confirm.html', {'uidb64': uidb64, 'token': token})
        return render(request, 'app1/reset_confirm.html', {'uidb64': uidb64, 'token': token})
    else:
        # Display error message fro invalid reset link
        messages.error(request, 'Invalid reset link. Please try again.')
        return render(request, 'app1/reset_confirm.html')


def password_reset_done(request):
    """Function to render the HTML page which will show password reset done successfully message"""
    return render(request, 'app1/reset_done.html')

def profile(request):
    """Function to render the profile page, show logout option if user was logged in, if not show login and registration option"""
    return render(request, 'app1/profile.html')

