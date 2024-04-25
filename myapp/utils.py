import datetime
import time
import pytz
from datetime import datetime as dtt

'''Time Formatting'''
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')
dmY = "%d-%m-%Y"
Ymd = '%Y-%m-%d'
Ydm = '%Y-%d-%m'
mdY = "%m-%d-%Y"
IMp = "%I:%M %p"
HMS = "%H:%M:%S"
dBY = "%d %B,%Y"
dBYIMp = "%d %B,%Y %I:%M %p"
YmdHMS = "%Y-%m-%d %H:%M:%S"
dmYHMS = "%d-%m-%Y %H:%M:%S"
YmdTHMSf = "%Y-%m-%dT%H:%M:%S.%f"
YmdHMSf = "%Y-%m-%d %H:%M:%S.%f"
YmdHMSfz = "%Y-%m-%d %H:%M:%S.%f%z"
YmdTHMSfz = "%Y-%m-%dT%H:%M:%S.%f%z"

class TimeFormatException(Exception):
    """
        UserDefined exception to hadle time format error

    """
    def __int__(self):
        super().__init__("TimeFormatError...Time should be in HH:MM:SS format")

def generate_current_date():

    timezone=pytz.timezone("Asia/Kolkata")

    now_=datetime.datetime.now().astimezone(timezone)

    return now_

  