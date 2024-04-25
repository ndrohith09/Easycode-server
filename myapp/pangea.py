import base64
import json
import requests
from django.conf import settings
import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import AuthN, FileScan, Audit,Redact,Share,IpIntel,UserIntel
from pangea.services.share.share import LinkType , ShareLinkItemBase , AuthenticatorType
from pangea.tools import logger_set_pangea_config
from io import BytesIO, BufferedReader , open
import base64

from pangea.services.vault.models.common import KeyPurpose
from pangea.services.vault.models.symmetric import SymmetricAlgorithm
from pangea.services.vault.vault import Vault
from pangea.utils import str2str_b64


token =  settings.PANGEA_AUDIT_TOKEN #"pts_ubignpagyjsy6c4w3ptlfhs642oso7hf" #os.getenv("PANGEA_AUDIT_TOKEN")
domain =  settings.PANGEA_DOMAIN #"aws.us.pangea.cloud" #os.getenv("PANGEA_DOMAIN")
config = PangeaConfig(domain=domain)

audit = Audit(token, config=config, logger_name="audit")
logger_set_pangea_config(logger_name=audit.logger.name)

authn = AuthN(token, config=config)
share = Share(token, config=config, logger_name="share")
filescan = FileScan(token, config=config, logger_name="file_scan")

intel = IpIntel(token, config=config)
userintel = UserIntel(token, config=config)

redact = Redact(token, config=config)
vault = Vault(token, config=config)

def authn_profile_get(email):
    try: 
        response = authn.user.profile.get(
        email=email,
            )
        print("Response" , response.result)
        return {
                "status": "success",
                "message": "Sharable Link deleted successfully",
                "body" :  response.result.json() 
                }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
        return {
            "status": "error",
            "message": "Audit log creation failed",
            "body" : e.response.summary
        }
 

def delete_share_link(id):
    try: 
        response = share.share_link_delete(
        ids=[id]
        ) 
        print("Response" , response)
        return {
                "status": "success",
                "message": "Sharable Link deleted successfully",
                "body" :  None 
                }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
        return {
            "status": "error",
            "message": "Audit log creation failed",
            "body" : e.response.summary
        }

def create_share_link(filePath, password) :

    try:     
        with open(filePath, "rb") as f:
            share_response = share.put(file=f)

            print(f"Response: {share_response.result.object}") 
            # print(f"Response: {share_response.result.json()}" , type({share_response.result.json()}))
            sid = share_response.result.object.id
            create_response = share.share_link_create(
            links=[
                    {
                        'targets': [sid],
                        'link_type': LinkType.DOWNLOAD,
                        'authenticators': [ 
                            {
                                "auth_type": AuthenticatorType.PASSWORD,
                                "auth_context": password,
                            }

                        ],
                    }
                ],
            )
            print("--------- Share Response ---------------") 
            print(create_response.result.share_link_objects[0]) 
            link = create_response.result.share_link_objects[0].link 

            return {
                "status": "success",
                "message": "Sharable Link created successfully",
                "body" : {
                    "link" : link
                },
                }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
        return {
            "status": "error",
            "message": "Audit log creation failed",
            "body" : e.response.summary
        }


def file_scan(filePath) : 

    try:     
        with open(filePath, "rb") as f:
   
            file_response = filescan.file_scan(file=f, verbose=True, provider="crowdstrike")
            json_res = json.loads(file_response.result.json())            
            print(f"Response: {json_res}")
            return {
                "status": "success",
                "message": "File scan successfully",
                "body" : json_res['data']
                }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
        return {
            "status": "error",
            "message": "Audit log creation failed",
            "body" : e.response.summary.json()
        }

def make_auditlog(message,action,actor,target,status,source):
    print("---------inside auditlog---------------")
    try:
        log_response = audit.log(
            message=message,
            action=action,
            actor=actor,
            target=target,
            status=status,
            source=source,
            verbose=True,
        )
        # log_response = audit.log(message=msg, verbose=False)
        # print(f"Response: {log_response.result}")
        return {
            "status": "success",
            "message": "Audit log created successfully",
            "body" : log_response.result.json()
        }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

        return {
            "status": "error",
            "message": "Audit log creation failed",
            "body" : e.response.summary.json()
        }

def redact_text(message):
    try:
        redact_response = redact.redact(text=message)
        print(f"Response: {redact_response.result}")
        json_res = json.loads(redact_response.result.json())
        print(type(json_res))

        return {
            "status": "success",
            "message": "Redacted created successfully",
            "body" : json_res['redacted_text']
        }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

        return {
            "status": "error",
            "message": "Redacted creation failed",
            "body" : e.response.summary.json()
        }

def ip_geolocate(ip):

    try:
        # response = intel.reputation(ip=ip, provider="crowdstrike", verbose=True, raw=True)
        response = intel.geolocate(ip=ip, provider="digitalelement", verbose=True, raw=True)
        # print(f"Response: {response.result}")
        json_res = json.loads(response.result.json())
        # print(json_res)
        json_data ={
            "ip": json_res['parameters']['ip'],
            "country": json_res['raw_data']['country'],
            "connection_type": json_res['raw_data']['connection_type'],
            "latitude": json_res['raw_data']['latitude'],
            "longitude": json_res['raw_data']['longitude']
        }        
        print("--------IP Geolocate----------")
        print(json_data)
        return {
            "status": "success",
            "message": "Ip geolocated successfully",
            "body" : json_data
        }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

        return {
            "status": "error",
            "message": "IP geolocation failed",
            "body" : e.response.summary.json()
        }      

def ip_reputation(ip):
    # print("----------------------------------------------------")
    # print(domain)
    # print(intel)
    # print(ip)
    # response = intel.reputation(ip="192.168.189.145", provider="crowdstrike", verbose=True, raw=True)
    # print(f"Response: {response.result}")
    # print("----------------------------------------------------")
    try:
        response = intel.reputation(ip=ip, provider="crowdstrike", verbose=True, raw=True)
        print(f"Response: {response.result}")
        json_res = json.loads(response.result.json())

        json_data ={
            "score": json_res['data']['score'],
            "verdict": json_res['data']['verdict']
        }        
  
        return {
            "status": "success",
            "message": "Ip reputation successfully",
            "body" : json_data
        }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

        return {
            "status": "error",
            "message": "IP reputation failed",
            "body" : e.response.summary.json()
        }      

def user_email_breached_check(email):

    try:
        response = userintel.user_breached(email=email, provider="spycloud", verbose=True, raw=True)
        json_res = json.loads(response.result.json())

        count = json_res['data']['breach_count']
        
        breached = True
        if count <= 10:
            breached = False

        return {
            "status": "success",
            "message": "User breach email successfully",
            "body" : {
                "breach_count": count,
                "breached": breached
            }
        }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

        return {
            "status": "error",
            "message": "User breach email check failed",
            "body" : e.response.summary.json()
        }      

def get_asymmetric_key(vault_name):
    """----------Send a api request to /v1/list to get the list of vaults------------"""
    vault_list_url = "https://vault.aws.us.pangea.cloud/v1/list"
    request_headers = {
        "Authorization": "Bearer " + settings.PANGEA_API_KEY ,
        "Content-Type": "application/json"
    }
    raw_data = {
        "filter":{
            "name":vault_name  #"zpay-pin"
        }
    }

    get_vaults = requests.post(vault_list_url, headers=request_headers, data=json.dumps(raw_data))
    vaults = get_vaults.json()
    # print("-----asymmetric key vaults-----")
    # print(vaults)

    vault_id = ""

    """if status is not success return the error message"""
    if vaults['status'] != "Success":
        return {
            "status": "error",
            "message": "Vault list failed",
            "body" : None
        }

    chk_count = vaults['result']['count']
    if chk_count == 0:
        """Create a vault if it is not available"""
        vault_create_url = "https://vault.aws.us.pangea.cloud/v1/key/generate"

        if vault_name == "zp_pin_vault":
            vault_create_payload = {
                "type":"asymmetric_key",
                "purpose":"encryption",
                "algorithm":"RSA-OAEP-2048-SHA256",
                "name":vault_name
            }
        else:
            vault_create_payload = {
                "type":"symmetric_key",
                "purpose":"encryption",
                "algorithm":"AES-CFB-128",
                "name":vault_name
            }
        create_vault = requests.post(vault_create_url, headers=request_headers, data=json.dumps(vault_create_payload))
        vault = create_vault.json()
        # print("-----asymmetric key create vault-----")
        # print(vault)
        """if status is not success return the error message"""
        if vault['status'] != "Success":
            return {
                "status": "error",
                "message": "Vault creation failed",
                "body" : None
            }
        else:
            vault_id = vault['result']['id']
            return {
                "status": "success",
                "message": "Vault creation success",
                "body" : {
                    "vault_id": vault_id
                }
            }
    else:
        """if status is not success return the error message"""
        if vaults['status'] != "Success":
            return {
                "status": "error",
                "message": "Vault creation failed",
                "body" : None
            }
        else:
            vault_id = vaults['result']['items'][0]['id']
            return {
                "status": "success",
                "message": "Vault creation success",
                "body" : {
                    "vault_id": vault_id
                }
            }
        
def encrypt_vault(message,vault_name):
    #Step-1 : Generate a asymmetric key pair and store it in a vault if it is not available
    #Step-2 : Transform the message to Base64Encode and encrypt it with the pangea asymmetric public key id,msg
    #Step-3 : Store the encrypted message in a our Database
    #Step-4 : Decrypt the message with the pangea asymmetric private key id,msg
    
    """Step-1"""
    get_key = get_asymmetric_key(vault_name)
    if get_key['status'] != "success":
        return {
            "status": "error",
            "message": "Vault creation failed",
            "body" : None
        }
    else:
        vault_id = get_key['body']['vault_id']

    """Step-2"""
    # encrypt a message and return cipher text
    try:
        msg = str2str_b64(message)
        encrypt_response = vault.encrypt(vault_id, msg)
        cipher_text = encrypt_response.result.cipher_text
        print(cipher_text)
        return {
            "status": "success",
            "message": "Encryption success",
            "body" : {
                "cipher_text": cipher_text
            }
        }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

        return {
            "status": "error",
            "message": "Encryption failed",
            "body" : e.response.summary.json()
        }
        
def decrypt_vault(cipher_text,vault_name):
    #Step-1 : Generate a asymmetric key pair and store it in a vault if it is not available
    #Step-2 : Transform the message to Base64Encode and encrypt it with the pangea asymmetric public key id,msg
    #Step-3 : Store the encrypted message in a our Database
    #Step-4 : Decrypt the message with the pangea asymmetric private key id,msg
    
    """Step-1"""
    get_key = get_asymmetric_key(vault_name)
    if get_key['status'] != "success":
        return {
            "status": "error",
            "message": "Vault creation failed",
            "body" : None
        }
    else:
        vault_id = get_key['body']['vault_id']
    print("----decrypt------")
    print(f"vault_id : {vault_id}")

    """Step-4"""
    # decrypt a cipher message and return plain text
    try:
        decrypt_response = vault.decrypt(vault_id, cipher_text)
        b64_plain_text = decrypt_response.result.plain_text
        plain_text = base64.b64decode(b64_plain_text).decode('utf-8')

        print(f"plain_text : {plain_text}")
        return {
            "status": "success",
            "message": "Decryption success",
            "body" : {
                "plain_text": plain_text
            }
        }
    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")

        return {
            "status": "error",
            "message": "Decryption failed",
            "body" : e.response.summary.json()
        }
