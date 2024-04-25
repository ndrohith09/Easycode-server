from django.urls import path

from .views import *

urlpatterns = [
    path('services/', PangeaServices.as_view(), name="services"), #added
    path('settings/', PangeaSettings.as_view(), name="settings"), #added
    path('database/', Database.as_view(), name="settings"), #added
    path('storage/', Storage.as_view(), name="storage"), #added
    path('login/', UserLogin.as_view(), name="login"), #added
    path('register/', RegisterUser.as_view(), name="register"), #added
    path('apiflow/', Api.as_view(), name="api"), #added
    path('mongodb/', MongoDatabase.as_view(), name="api"), #added

]