from django.urls import path
from scanner import views

urlpatterns = [
    path('', views.home, name='home'),
    path('api/scan/', views.scan_file, name='scan_file'),
]