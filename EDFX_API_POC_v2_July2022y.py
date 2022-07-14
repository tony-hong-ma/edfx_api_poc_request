from msilib.schema import Error
from pywebio.output import *
from pywebio.input import * 
import time

import requests as rq # noqa
import json as json
import pandas as pd
import datetime as dt
import os as os
import fnmatch as fm
import numpy as np
import re
import csv

from io import StringIO

from User_CE import usrnm,pswd

### Logging block ####
import logging

# These two lines enable debugging at httplib level (requests->urllib3->http.client)
# You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
# The only thing missing will be the response.body which is not logged.
try:
    import http.client as http_client
except ImportError:
    # Python 2
    import http.client as http_client
http_client.HTTPConnection.debuglevel = 1

# You must initialize logging, otherwise you'll not see debug output.
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

### end of logging block

# Disable the unverified HTTPS request messages
rq.packages.urllib3.disable_warnings(rq.packages.urllib3.exceptions.InsecureRequestWarning)

def app():
    cwd = os.getcwd()

    # Create login page
    login_details = input_group("Login Details", [
     input('Username', name='username', type=TEXT),
     input('Password', name='password', type=PASSWORD)])

    id_token = get_auth_token(login_details['username'], login_details['password'])

    placeholder_txt = "Select File"

    default_output_file_name = "DefaultFile.csv"
    batch_size = 100

    # Look up input_group to add multiple inputs to a page
    input_file = file_upload('Upload a csv file with a BVD_ID_NUMBER column', accept='.csv', placeholder=placeholder_txt)
    """ output_file_name = input('Output file name',type=TEXT,placeholder=default_output_file_name)
    batch_size = input(label='Batch size',type=NUMBER,placeholder="Enter batch size",validate=validate_batch_size)
    processing_mode = radio("Processing mode", options=["Synchronous","Asynchronous"])

    if output_file_name == '':
        output_file_name = default_output_file_name

    print(output_file_name)
    print(batch_size)
    print(processing_mode) """
    put_text('File progress:').style('font-weight: bold')


    put_processbar('fileProgress',label='File Processing Progress')
 
    

    df = create_dataframe(input_file)

    batch_count = calc_number_of_batches(len(df), batch_size)

    pds_list = []
    
    for count, batch in enumerate(np.array_split(df, batch_count)):
        if(count%50 == 0):
          # renew the token
          id_token = get_auth_token(login_details['username'], login_details['password'])

        try:
            payload = create_pd_search_payload(batch)
        except:
            put_text("Processing terminated.")
        pds_response = send_request(id_token, payload)
        #pds_list = process_pds_response(pds_response)
        pds_list = pds_list + process_pds_response(pds_response)
        #print(input['filename'])

        # Progress bar stuff
        entitiesProcessed = min((count+1)*batch_size,len(df))
        progress_pct = entitiesProcessed/len(df)
        if progress_pct == 1:
            progress_pct = 0.999 # a little cheat to leave the final percentage for file writing
        set_processbar('fileProgress',progress_pct)
        with use_scope('a'):
            clear('a')
            put_text('Processed ' + str(entitiesProcessed) + '/' + str(len(df)) + ' entities') 

    with use_scope('b'):
        put_text('Writing to file...')
    output_file_name = write_to_file(pds_list, input_file['filename']) # creating file name should be a separate fn
    with use_scope('b'):
        clear('b')
        put_text(' ') # Cheat to add a line
        put_text('File ready: ').style('font-weight: bold')
        put_text(output_file_name).style('font-style: italic')

    set_processbar('fileProgress',entitiesProcessed/len(df))


def create_dataframe(input_file):
    file_contents = StringIO(str(input_file['content'],'utf-8'))
    #print(pd.read_csv(file_contents))
    return pd.read_csv(file_contents)

def list_to_dataframe(file_content):
    with open("data.csv", "w") as csv_file:
        writer = csv.writer(csv_file, delimiter = ',')
        for line in file_content:
            writer.writerow(re.split('\s+',line))
    return pd.read_csv("data.csv") 

def validate_batch_size(batch_size):
    if batch_size < 1:
        return "Batch size must be greater than or equal to zero."
    elif batch_size > 10000:
        return "Batch size must be smaller than 10,000."

def get_auth_token(username, password):
    auth_url = "https://sso.moodysanalytics.com/sso-api/v1/token"
    grant_type = "password" # with underscore
    username = usrnm
    password = pswd
    #username = "ewtkuser"
    #password = "qaqaqa"

    scope = "openid"
    payload = {'username': username, 'password': password, 'grant_type': grant_type, 'scope': scope}

    try:
        auth_response = rq.post(auth_url, payload)
        auth_data = json.loads(auth_response.text)
    except:
        print("Authentication Error")
        put_text("Authentication Error")
        #toast('New messages', position='right', color='#2188ff', duration=0)
        popup('Authentication Error', 'Check username and password', size=PopupSize.SMALL)
    return auth_data['id_token'] # Why don't we use access_tokens??

def create_pd_search_payload(df):

    entity_list = []

    try: 
        for i in df['BVD_ID_NUMBER']:
            entity_list.append({ "entityId" : i})
    except KeyError as err:
        err_msg = "Key error: {0}. Check file format.".format(err)
        popup('Key Error', err_msg, size=PopupSize.SMALL)
        print(err_msg)
        raise

    payload = json.dumps({
        "startDate": "2022-04-01",
        "endDate": "2022-07-08",
        "historyFrequency": "monthly",
        "asyncResponse": False,
        "modelParameters": {
        "fso": False,
        "modelId": "string"
        },
        "includeDetail": {
        "resultDetail": False,
        "inputDetail": False,
        "modelDetail": True
        },
        "entities": entity_list # was entity_list[0:ROWS_TO_READ]
    })    
    print(payload)
    #return d


    return payload # this is vital, converts python object into JSON string!

def send_request(id_token, payload):
    api_url_base = 'https://api.edfx.moodysanalytics.com/edfx/v1/'
    headers = {'Authorization' : 'Bearer ' + id_token, 'Content-Type': 'application/json'}
    #headers = {'Authorization' : 'Bearer ' }

    return rq.post(api_url_base + 'entities/pds', data=payload, headers=headers, verify=False)


def process_pds_response(pds_response):
    # work in lists to avoid growing a dataframe
    no_pd_list = []
    pd_list = []

    pds_data = json.loads(pds_response.text)
    #for index, entity in df.iloc[0:10].iterrows():
    for entity in pds_data['entities']:
      try:
        # You only get a message if the search returned nothing
        no_pd_list.append([entity['entityId'],entity['message']])
      except:
        pd_list.append([entity['entityId'], entity['asOfDate'], str(entity['pd']), entity['impliedRating'], 
                        entity['confidence'], entity['confidenceDescription'],
                        entity['modelDetails']['modelId']])

    return pd_list + no_pd_list
    print(final_list)
    entity_info_df = pd.DataFrame(final_list, columns = ['BVD ID Number', 'Calculation Date', '1 Yr PD', 'CCA Implied Rating', 'Confidence Code', 'Confidence Description'])
    print(entity_info_df)    
    entity_info_df.to_csv('Test_SearchResults.csv',index=False)

def write_to_file(pds_list, input_file_name):
    entity_info_df = pd.DataFrame(pds_list, columns = ['BVD_ID_NUMBER', 'Calculation Date', '1 Yr CCA PD', 'CCA Implied Rating', 
                                                        'Confidence Code', 'Confidence Description',
                                                        'Model ID'])  
    #entity_info_df = pd.DataFrame(pds_list)  
    output_file_name = os.path.splitext(input_file_name)[0] + '_PD_Results.csv'
    entity_info_df.to_csv(output_file_name,index=False)
    return os.getcwd() + '\\' + output_file_name

def calc_number_of_batches(line_count, batch_size):
    #ROWS_TO_READ = len(df)
    CHUNK_SIZE = 1 # the only way to get those that are not found
    batch_count = 1
    if batch_size < line_count:
        batch_count = (line_count-1)//batch_size + 1 # rely on integer math here!
    return batch_count

def get_model():
    return True

app()
