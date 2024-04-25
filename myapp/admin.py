from django.contrib import admin

# Register your models here.
from .models import *

admin.site.register(UserModel)
admin.site.register(PangeaSecurityModel)    
admin.site.register(PangeaServiceModel) 
admin.site.register(DatabaseModel)
admin.site.register(StorageModel) 
admin.site.register(ApiModel) 
admin.site.register(FlowModel) 
admin.site.register(ProjectModel) 