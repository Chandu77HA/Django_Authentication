from django.urls import path,re_path
from app1 import views


urlpatterns = [

    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('password_reset_request/', views.password_reset_request, name='password_reset_request'),
    path('password_reset/done/', views.password_reset_done, name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('profile/', views.profile, name='profile'),
    
]
