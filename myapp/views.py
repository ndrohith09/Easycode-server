from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from backend.responsecode import display_response
from django.db.models import Q
from django.conf import settings
from .views import *
from .models import *
from .serializers import *
from .pangea import make_auditlog,authn_profile_get, delete_share_link, file_scan, create_share_link,redact_text, ip_geolocate, ip_reputation, user_email_breached_check, encrypt_vault, decrypt_vault
from backend.mail import sending_mail
from backend.auth import UserAuthentication
import uuid
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi  
import pangea.exceptions as pe
from pangea.services import Audit,Redact,IpIntel,UserIntel
import requests

# Create your views here.

DATBASE_URI_PIN_VAULT = "db_pin_vault"
PASSWORD_VAULT = "password_vault"

class UserLogin(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request, fromat=None):
        data = request.data
        pid = data.get("pid", None)
        otp = data.get("otp", None)

        if pid in ["", None] or otp in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide user data",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )

        user_instance = UserModel.objects.filter(pid=pid).first()
        if user_instance is None:
            return display_response(
                msg="FAIL",
                err="User does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )

 
        """---Decrypt the cipher password and send to the server---"""
        # PANGEA_DECRYPTION_PIN
        # pass_decrypt = decrypt_vault(user_instance.password,PASSWORD_VAULT)
        # print("--------------")
        # print(pass_decrypt)
        # if pass_decrypt['status'] != "success":
        #     return display_response(
        #         msg="FAIL",
        #         err="Something went wrong in newpin encryption",
        #         body=None,
        #         statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
        #     )
        # password_plain = pass_decrypt['body']['plain_text']
        print("----credits----")
        print(user_instance.email)
        print(user_instance.password)
        payload = {
            "email": user_instance.email,
            "password": user_instance.password
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.PANGEA_API_KEY}",
        }
        api_endpoint_url = "https://authn.aws.us.pangea.cloud/v1/user/login/password"
        response = requests.post(
            api_endpoint_url, json=payload, headers=headers)
        print(response.status_code)
        if response.status_code == 200:
            # Request was successful
            print(response.json())

            if response.json()['result'] == None:
                return display_response(
                    msg="FAIL",
                    err="Invalid pin",
                    body=None,
                    statuscode=status.HTTP_404_NOT_FOUND
                )

            return display_response(
                msg="SUCCESS",
                err=None,
                body={
                    "access_token": response.json()["result"]['active_token']['token'],
                    "refresh_token": response.json()["result"]['refresh_token']['token'],
                    "pid": pid
                },
                statuscode=status.HTTP_200_OK
            )
        else:
            # Request failed
            print("Error:", response.status_code)
            return display_response(
                msg="FAIL",
                err="Invalid pin",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )


class RegisterUser(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request, fromat=None):
        data = request.data
        name = data.get("name", None) 
        email = data.get("email", None) 
        password = data.get("password", None) 

        if email in ["", None] or password in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide user data",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )

        breached_check = user_email_breached_check(email)
        if breached_check['status'] == 'success':
            if breached_check['body']['breached'] == True:
                return display_response(
                    msg="FAIL",
                    err="Email has been breached.Try new email",
                    body=None,
                    statuscode=status.HTTP_406_NOT_ACCEPTABLE
                )

        # check if user already exists
        user_instance = UserModel.objects.filter(email=email).first()
        if user_instance is not None:
            return display_response(
                msg="FAIL",
                err="Email already exists",
                body=None,
                statuscode=status.HTTP_409_CONFLICT
            )

 
        """Encrypt the password"""
        pass_encrypt = encrypt_vault(password, PASSWORD_VAULT)
        print("-------Password Encrypt-------")
        print(pass_encrypt)
        if pass_encrypt['status'] != "success":
            return display_response(
                msg="FAIL",
                err="Something went wrong in password encryption",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        password_cipher = pass_encrypt['body']['cipher_text']
        print("----cipher text-----")
        print(password_cipher)
        api_endpoint_url = "https://authn.aws.us.pangea.cloud/v1/user/create"
        payload = {
            "email": email,
            "authenticator": password_cipher,
            "profile": {
                "first_name": name, 
            },
            "id_provider": "password",
            "verified": True
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.PANGEA_API_KEY}",
        }

        response = requests.post(
            api_endpoint_url, json=payload, headers=headers)
        print("---Create user response---")
        print(response.json())
        if response.status_code == 200:
            # create user in our database
            user_instance = UserModel.objects.create(
                email=email,
                pid=response.json()["result"]["id"], 
                name=name,
                password=password_cipher
            )
            user_instance.save() 

            return display_response(
                msg="SUCCESS",
                err=None,
                body={
                    "pid": user_instance.pid,
                },
                statuscode=status.HTTP_200_OK
            )
        else:
            # Request failed
            print("Error:", response.status_code)
            return display_response(
                msg="FAIL",
                err="Invalid pin",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )


class PangeaServices(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request):
        user = request.user 
        service_instances = PangeaServiceModel.objects.all()
        if service_instances is None:
            return display_response(
                msg="FAIL",
                err="Services does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
      
        serializer = PangeaServiceSerializer(
            service_instances, many=True, context={"request": request}) 
    
        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "services": serializer.data
            },
            statuscode=status.HTTP_200_OK
        )
 

    def put(self, request):
        user = request.user
        # pid = user.pid

        data = request.data
        service_pid = data.get("pid", None) 
        service_is_active = data.get("is_active", None)
        print("data", data)

        if service_pid in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide service id",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )

        get_service = PangeaServiceModel.objects.filter(
            pid=service_pid).first()
        if get_service is None:
            return display_response(
                msg="FAIL",
                err="Service does not exist",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )
                 
        get_service.is_active = service_is_active
        get_service.save()

        try: 
            pangea_res = make_auditlog(
                message=f"{get_service.name} Service set to inactive",
                action="Service Deactive",
                actor=None,
                target=f'{get_service.name} Service Deactive Successful',
                status="SUCCESS",   
                source="Service Update"
            )
            print("----pangea res--------")
            print(pangea_res)
        except Exception as e:
            print(e)

        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "pid" : get_service.pid,
                "is_active": get_service.is_active
            },
            statuscode=status.HTTP_200_OK
        )


    def post(self, request):
        user = request.user
        # pid = user.pid

        data = request.data
        service_pid = data.get("pid", None) 
        service_token = data.get("token", None)
        

        if service_pid in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide service id",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )

        get_service = PangeaServiceModel.objects.filter(
            pid=service_pid).first()
        if get_service is None:
            return display_response(
                msg="FAIL",
                err="Service does not exist",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )
                 
        get_service.token = service_token
        get_service.is_active = True 
        get_service.save()

        try: 
            pangea_res = make_auditlog(
                message=f"{get_service.name} Service token is set",
                action="Service Token",
                actor=None,
                target=f'{get_service.name} Set Token Successful',
                status="SUCCESS",
                source="Set Token"
            )
            print("----pangea res--------")
            print(pangea_res)
        except Exception as e:
            print(e)

        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "pid" : get_service.pid, 
            },
            statuscode=status.HTTP_200_OK
        )

 
class PangeaSettings(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request):
        user = request.user 
        security_instances = PangeaSecurityModel.objects.all()
        if security_instances is None:
            return display_response(
                msg="FAIL",
                err="Security does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
      
        serializer = PangeaSecuritySerializer(
            security_instances, many=True, context={"request": request}) 
    
        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "security": serializer.data[0]
            },
            statuscode=status.HTTP_200_OK
        )
    
    def put(self, request):
        user = request.user
        # pid = user.pid

        data = request.data
        pid = data.get("pid", None) 
        domain = data.get("domain", None) 
        api_key = data.get("api_key", None)
        print("user", data)

        if pid in ["", None]:
            return display_response(
                msg="FAIL",
                err="Please provide security id",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )

        get_security = PangeaSecurityModel.objects.filter(
            pid=pid).first()
        if get_security is None:
            return display_response(
                msg="FAIL",
                err="Security does not exist",
                body=None,
                statuscode=status.HTTP_404_NOT_FOUND
            )
            
        if domain :
            get_security.domain =  domain
        if api_key :        
            get_security.api_key =  api_key
        get_security.save()

        try: 
            pangea_res = make_auditlog(
                message=f"Security settings updated",
                action="Service Deactive",
                actor=None,
                target=f'Security Settings Updated Successful',
                status="SUCCESS",   
                source="Security Update"
            )
            print("----pangea res--------")
            print(pangea_res)
        except Exception as e:
            print(e)

        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "pid" : get_security.pid, 
            },
            statuscode=status.HTTP_200_OK
        )


class Database(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request):
        user = request.user 
        db_instances = DatabaseModel.objects.all()
        if db_instances is None:
            return display_response(
                msg="FAIL",
                err="Services does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
      
        serializer = DatabaseSerializer(
            db_instances, many=True, context={"request": request}) 
    
        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "databases": serializer.data
            },
            statuscode=status.HTTP_200_OK
        )
 

    def post(self, request):
        user = request.user
        # pid = user.pid
        id = uuid.uuid4()
        data = request.data
        type = data.get("type", None)  
        uri = data.get("uri", None) 
        name = data.get("name", None)
        print("data", data)

        if uri in ["", None] or type in ["" , None] or name in ["",None]:
            return display_response(
                msg="FAIL",
                err="Please provide all fields",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )
         
        client = MongoClient(uri, server_api=ServerApi('1')) 
        
    
        try:
            client.admin.command('ping')
            print("Pinged your deployment. You successfully connected to MongoDB!")

            """Encrypt the password"""
            pass_encrypt = encrypt_vault(uri, DATBASE_URI_PIN_VAULT)
            print("-------Password Encrypt-------")
            print(pass_encrypt)
            if pass_encrypt['status'] != "success":
                return display_response(
                    msg="FAIL",
                    err="Something went wrong in uri encryption",
                    body=None,
                    statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            uri_cipher = pass_encrypt['body']['cipher_text']
        

            db_instance = DatabaseModel.objects.create(
                    pid= id,
                    name = name,
                    uri=uri_cipher,
                    type=type,
                    status='running', 
                )
            db_instance.save()  
        
        except Exception as e:
            print(e)
            return display_response(
                msg="FAIL",
                err="Error in Database Connection",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
 
        return display_response(
                msg="SUCCESS",
                err=None,
                body={
                    "pid": db_instance.pid,
                },
                statuscode=status.HTTP_200_OK
            )
  
 
    def delete(self, request):
        user = request.user 
        data = request.data
        pid = data.get("pid", None)   
        print("data", data)

        if pid in ["", None] :
            return display_response(
                msg="FAIL",
                err="Please provide id fields",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )
          
        db_instance = DatabaseModel.objects.filter(pid = pid).first()
        if db_instance in ["", None] :
            return display_response(
                msg="FAIL",
                err="Database instance not found",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )
        try:
            db_instance.delete()    
            return display_response(
                msg="SUCCESS",
                err=None,
                body={
                    "message": "Database deleted succesfully",
                },
                statuscode=status.HTTP_204_NO_CONTENT
            )
    
        except Exception as e:
            print(e)
            return display_response(
                msg="FAIL",
                err=f"An error occurred: {str(e)}",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
 
class Storage(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request):
        user = request.user 
        storage_instances = StorageModel.objects.all()
        if storage_instances is None:
            return display_response(
                msg="FAIL",
                err="Storage does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
      
        serializer = StorageSerializer(
            storage_instances, many=True, context={"request": request}) 
    
        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "storage": serializer.data
            },
            statuscode=status.HTTP_200_OK
        )
 
    def post(self, request): 
        data = request.data
        file_obj = request.data['file']
        password = request.data['password']
        name = request.data['file_name']
        print("==================file data====================")  
        print("data", data, file_obj , file_obj.name)  
        try:
            storage_instance = StorageModel.objects.create(
                    pid= uuid.uuid4(),
                    name = name,
                    score = '',
                    verdict='',
                    file=file_obj,
                    sharable_link='', 
                )
            storage_instance.save()   
          
        except Exception as e:
            print(e)
            return display_response(
                msg="FAIL",
                err=f"An error occurred: {str(e)}",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        try :
            file_scan_res = file_scan(storage_instance.file.path)  

            print("file_scan_res", file_scan_res) 
            print("file_scan_res", file_scan_res['body']['verdict'])
            storage_instance.verdict = file_scan_res['body']['verdict']
            storage_instance.score = file_scan_res['body']['score'] 
            share_res = create_share_link(storage_instance.file.path ,password)
            print("share_res", share_res)
            storage_instance.sharable_link = share_res['body']['link']  
            storage_instance.save()   

            return display_response(
                msg="SUCCESS",
                err=None,
                body={
                    "message": "File added to Storage succesfully", 
                    "share_res": share_res,
                    "file_scan_res": file_scan_res
                },
                statuscode=status.HTTP_201_CREATED
            )
    
        except Exception as e:
            print(e)
            return display_response(
                msg="FAIL",
                err=f"An error occurred: {str(e)}",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


    def delete(self, request):
        data = request.data
        pid = data.get("pid", None)   
        sharable_link = data.get("sharable_link", None)    

        if pid in ["", None] or sharable_link in ["", None] :
            return display_response(
                msg="FAIL",
                err="Please provide id fields",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )
        storage_instance = StorageModel.objects.get(pid=pid)
         
        if storage_instance in ["", None] :
            return display_response(
                msg="FAIL",
                err="File instance not found",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )
        try:
            storage_instance.delete()   
            # delete_share_link(sharable_link)
            return display_response(
                msg="SUCCESS",
                err=None,
                body={
                    "message": "File deleted succesfully",
                },
                statuscode=status.HTTP_204_NO_CONTENT
            )
    
        except Exception as e:
            print(e)
            return display_response(
                msg="FAIL",
                err=f"An error occurred: {str(e)}",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
 
class Api(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request):
        user = request.user 

        # email = request.data.get('email')
        # response = authn_profile_get(email)
        # email = response['email']
        # project_member = ProjectModel.objects.filter(user__email=email).first()
        # project = project_member.project
        # api_instance = ApiModel.objects.filter(api__in=project.storages.all())
        
        api_instance = ApiModel.objects.all()
        if api_instance is None:
            return display_response(
                msg="FAIL",
                err="API does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
      
        serializer = ApiSerializer(
            api_instance, many=True, context={"request": request}) 
    
        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "api": serializer.data
            },
            statuscode=status.HTTP_200_OK
        )
    
    def post(self, request):
        name = request.data['name']
        url = request.data['url']
        mode = request.data['mode'] 

        if url in ["", None] or name in ["" , None] or mode in ["",None]:
            return display_response(
                msg="FAIL",
                err="Please provide all fields",
                body=None,
                statuscode=status.HTTP_400_BAD_REQUEST
            )   
        
        id =  str(uuid.uuid4())[:7] 
        d_url = f"{settings.BASE_SITE_URL}/{mode}/{id}/{url}"

        try:
            flow_instance = FlowModel.objects.create(
                    flow_id= uuid.uuid4(),  
                    nodes = {},
                    edges = {},
            )
        except Exception as e:
            print(e)
            return display_response(
                msg="FAIL",
                err=f"An error occurred: {str(e)}",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        try:

            api_instance = ApiModel.objects.create(
                    api_id= id,
                    name = name,
                    url = url, 
                    mode= mode, 
                    is_active=True, 
                    flow = flow_instance,
                    developement_url = d_url
                )
            api_instance.save()   

            return display_response(
                msg="SUCCESS",
                err=None,
                body={
                    "message": "API Added succesfully", 
                    "api_id": api_instance.api_id, 
                },
                statuscode=status.HTTP_201_CREATED
            )
          
        except Exception as e:
            print(e)
            return display_response(
                msg="FAIL",
                err=f"An error occurred: {str(e)}",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
 


class MongoDatabase(APIView):
    authentication_classes = [UserAuthentication]
    permission_classes = []

    def get(self, request):
        user = request.user 
        db_id = request.data.get('db_id') 
        
        db_instance = DatabaseModel.objects.get(pid=db_id)

        if db_instance is None:
            return display_response(
                msg="FAIL",
                err="API does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )

        uri = db_instance.uri
        connection_url = decrypt_vault(uri, DATBASE_URI_PIN_VAULT)
        print("connection_url", connection_url)
        print("connection_url", connection_url.get('body'))
        try:
            client = MongoClient(connection_url.get('body').get('plain_text'))
            collections = client.list_database_names()
            # database = client[collections[0]]
            database = client['test']

        except Exception as e:
            print(e)
            return display_response(
                msg="FAIL",
                err=f"An error occurred: {str(e)}",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        serializer = DatabaseSerializer(
            db_instance, context={"request": request}) 
    
        return display_response(
            msg="SUCCESS",
            err=None,
            body={
                "collections" : database,
                "database": serializer.data
            },
            statuscode=status.HTTP_200_OK
        )
    
 