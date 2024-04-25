from django.urls import path

from .views import *

urlpatterns = [
    path('development/<str:apiId>/<str:route>/', FlowApiProcess.as_view(), name="flowapiprocess"),
    path('break/', BreakdownResponse.as_view(), name='break'),
]