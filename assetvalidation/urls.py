from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home),
    path('csv-export/', views.csvexport, name='csvexport'),

]
urlpatterns+=staticfiles_urlpatterns()