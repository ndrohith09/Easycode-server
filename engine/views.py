from rest_framework.views import APIView
from .views import *
from pymongo.mongo_client import MongoClient
from rest_framework import status
from myapp.models import *
import json , bson
from bson import json_util
from backend.responsecode import display_response
from myapp.pangea import make_auditlog,authn_profile_get, delete_share_link, file_scan, create_share_link,redact_text, ip_geolocate, ip_reputation, user_email_breached_check, encrypt_vault, decrypt_vault
from myapp.serializers import *
from  .utils import convert_json_data
from .mail import sending_mail
from engine.parser import handle_parser_flow
 
class FlowApiProcess(APIView) :

    def get(self, request, *args, **kwargs):
        user = request.user 
        api_id = request.parser_context['kwargs']['apiId']
        route = request.parser_context['kwargs']['route'] 
        api_instance = ApiModel.objects.get(api_id=api_id) 
        if api_instance is None:
            return display_response(
                msg="FAIL",
                err="API does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
       
        flow_instance = FlowModel.objects.get(flow_id=api_instance.flow.flow_id) 
        print("flow_instance",flow_instance)
        flow_id = flow_instance.flow_id
        nodes = flow_instance.nodes
        edges = flow_instance.edges

        parser_response = handle_parser_flow(api_instance, flow_instance)

        flow_serializer = FlowSerializer(
            flow_instance, context={"request": request})  

        serializer = ApiSerializer(
            api_instance, context={"request": request}) 
    


        parser_response = handle_parser_flow(api_instance, flow_instance)
                   
        return display_response(
                msg="SUCCESS",
                err=None,
                body={       
                    "message" : 'Data fetch' ,
                    "result" : parser_response
                },
                statuscode=status.HTTP_200_OK
            )
        
    

    def post(self, request, *args, **kwargs):
        user = request.user
        data = request.data
        api_id = request.parser_context['kwargs']['apiId']
        route = request.parser_context['kwargs']['route']  
   
        api_instance = ApiModel.objects.get(api_id=api_id) 
        if api_instance is None:
            return display_response(
                msg="FAIL",
                err="API does not exist.Try signup",
                body=None,
                statuscode=status.HTTP_406_NOT_ACCEPTABLE
            )
       
        flow_instance = FlowModel.objects.get(flow_id=api_instance.flow.flow_id) 
        flow_id = flow_instance.flow_id
        nodes = flow_instance.nodes
        edges = flow_instance.edges


 

        try :
            parser_response = handle_parser_flow(api_instance, flow_instance)
                   
            return display_response(
                msg="SUCCESS",
                err=None,
                body={       
                    "message" : 'Data inserted' ,
                    "result" : parser_response
                },
                statuscode=status.HTTP_200_OK
            )
        
        except Exception as e:
            print(e)
            return display_response(
                msg="FAIL",
                err=f"An error occurred: {str(e)}",
                body=None,
                statuscode=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        



class BreakdownResponse(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request, **kwargs):
        data = request.data
        # Get the IP address of the client
        # print(request.META)
        # print(request.META.get('REMOTE_ADDR'))


        # PANGEA-IPREPUTATION
        """If the IP verdict is malicious then block the user"""
        # try:
        #     ip_address = request.META.get('REMOTE_ADDR')
        #     check_ip = ip_reputation(ip_address)
        #     if check_ip['status'] == 'success':
        #         if check_ip['body']['verdict'] == 'malicious':
        #             return display_response(
        #                 msg="FAIL",
        #                 err="Login failed. Malicious IP Found",
        #                 body=None,
        #                 statuscode=status.HTTP_404_NOT_FOUND
        #             )
        #     else:
        #         return display_response(
        #             msg="FAIL",
        #             err="Login failed. Malicious IP Found",
        #             body=None,
        #             statuscode=status.HTTP_404_NOT_FOUND
        #         )
        # except Exception as e:
        #     print(e)

        """Send a email to the user"""
        mail_res = sending_mail(
            request, "Verify your OTP", "Testing mail server", "****")
        print(f"Mail sent to {mail_res}")

        return display_response(
            msg="SUCCESS",
            err=None,
            body=data,
            statuscode=status.HTTP_200_OK
        )
