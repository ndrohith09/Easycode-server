from rest_framework.serializers import ModelSerializer
from .models import *

class UserSerializer(ModelSerializer):
	class Meta:
		model=UserModel
		fields='__all__'


class PangeaSecuritySerializer(ModelSerializer):
	class Meta:
		model=PangeaSecurityModel
		fields='__all__'


class PangeaServiceSerializer(ModelSerializer):
	class Meta:
		model=PangeaServiceModel
		fields='__all__'


class DatabaseSerializer(ModelSerializer):
	class Meta:
		model=DatabaseModel
		fields='__all__'
 

class FlowSerializer(ModelSerializer):
	class Meta:
		model=FlowModel
		fields='__all__'


class ApiSerializer(ModelSerializer):
	class Meta:
		model=ApiModel
		fields='__all__'

class StorageSerializer(ModelSerializer):
	class Meta:
		model=StorageModel
		fields='__all__'