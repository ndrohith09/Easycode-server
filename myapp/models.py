from django.db import models

# Create your models here.

class PangeaSecurityModel(models.Model):
    pid = models.CharField(max_length=256, primary_key=True, unique=True)
    api_key = models.CharField(max_length=255, null=True, blank=True)
    domain = models.CharField(max_length=255, null=True, blank=True)
    pangea_services = models.ManyToManyField('PangeaServiceModel', blank=True)  # Use ManyToManyField

class StorageModel(models.Model): 
    pid = models.CharField(max_length=256, primary_key=True, unique=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    verdict = models.CharField(max_length=255, null=True, blank=True)
    score = models.CharField(max_length=255, null=True, blank=True)
    sharable_link = models.CharField(max_length=255, null=True, blank=True)
    file = models.FileField(upload_to='storage_files/')  # 'storage_files/' is a subdirectory within MEDIA_ROOT
 

class DatabaseModel(models.Model): 

    TYPE_CHOICES = [
        ('mongoDB', 'MongoDB'),
    ]

    STATUS_CHOICES = [
        ('running', 'running'),
        ('inactive', 'inactive'),
        ('error', 'error'),
    ]
        
    pid = models.CharField(max_length=256, primary_key=True, unique=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    uri = models.CharField(max_length=255, null=True, blank=True)
    type = models.CharField(max_length=255, choices=TYPE_CHOICES, null=True, blank=True)
    status = models.CharField(max_length=255, choices=STATUS_CHOICES, default='inactive', null=True, blank=True)
     
class  PangeaServiceModel(models.Model):
    pid = models.CharField(max_length=256, primary_key=True, unique=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    token = models.CharField(max_length=255, null=True, blank=True)
    is_active = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.name}"

class UserModel(models.Model):
    pid = models.CharField(max_length=256, primary_key=True, unique=True) 
    name = models.CharField(max_length=50,null=True,blank=True) 
    email = models.CharField(max_length=50,null=True,blank=True) 
    password = models.CharField(max_length=255,null=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.pid}-{self.mobile}"
    
class ApiModel(models.Model): 
    api_id = models.CharField(max_length=256, primary_key=True, unique=True) 
    name = models.CharField(max_length=50,null=True,blank=True) 
    url = models.CharField(max_length=50,null=True,blank=True) 
    mode = models.CharField(max_length=50,null=True,blank=True) 
    is_active = models.BooleanField(default=False)  
    flow = models.ForeignKey('FlowModel', on_delete=models.CASCADE, null=True, blank=True)
    developement_url = models.CharField(max_length=255,null=True,blank=True) 

    def __str__(self):
        return f"{self.name}"

class FlowModel(models.Model):
    flow_id = models.CharField(max_length=256, primary_key=True, unique=True) 
    nodes = models.JSONField(null=True,blank=True) 
    edges = models.JSONField(null=True,blank=True) 

class ProjectModel(models.Model):
    pid = models.CharField(max_length=256, primary_key=True, unique=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    pangea_security = models.ForeignKey('PangeaSecurityModel', on_delete=models.CASCADE, null=True, blank=True)
    user = models.ForeignKey('UserModel', on_delete=models.CASCADE, null=True, blank=True)
    storages = models.ManyToManyField('StorageModel', blank=True )
    api = models.ManyToManyField('ApiModel', blank=True )
    database = models.ManyToManyField('DatabaseModel', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name