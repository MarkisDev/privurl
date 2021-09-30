from django.urls import path, include
from . import views
from django.conf.urls.static import static
from django.conf import settings

app_name = "api"


urlpatterns = [
    
    path('', views.home, name="home"),
    path('v1', views.api, name="api" )
    
]