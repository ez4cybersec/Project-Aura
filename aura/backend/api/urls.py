from django.urls import path
from . import views

urlpatterns = [
    path('scan/pcap/', views.upload_pcap, name='upload_pcap'),
]
