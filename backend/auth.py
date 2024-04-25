from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions

from myapp.models import UserModel
import jwt

def get_request_header(request):
	header=request.META.get('HTTP_AUTHORIZATION','')	
	return header

class UserAuthentication(BaseAuthentication):
    keyword="Bearer"

    def authenticate(self,request):

        auth=get_request_header(request).split()
        print(auth)
        if not auth or auth[0].lower()!=self.keyword.lower():
            raise exceptions.AuthenticationFailed(_('Not authorised! Token is not provided'))

        print("1")
        if(len(auth)==1):
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        token_=auth[1]

        try:

            user=UserModel.objects.filter(pid=token_)
            if user.exists():
                return (user[0],None)
            else:
                raise exceptions.AuthenticationFailed(_('Invalid token.'))
        
        except jwt.exceptions.InvalidSignatureError:
            raise exceptions.AuthenticationFailed(_('Invalid token given'))
        
        except jwt.exceptions.DecodeError:
            raise exceptions.AuthenticationFailed(_('Invalid token given'))
        
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed(_('Token expired'))
