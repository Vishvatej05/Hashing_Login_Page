from django.urls import path

from . import views


urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('accounts/', views.accounts_table, name='accounts_table'),
    path('accounts_table/', views.accounts_table),
    path('verify/<str:token>/', views.verify, name='verify'),
    path('forgot/', views.forgot_password, name='forgot_password'),
    path('reset/<str:token>/', views.reset_password, name='reset_password'),
]


