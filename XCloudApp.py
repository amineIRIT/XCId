import indy_vdr.ledger as indyledger
from indy_vdr import Pool, open_pool
from colorama import Fore, Style
from google.cloud import storage
import botocore.exceptions
import requests
import hashlib
import asyncio
import urllib
import base64
import shutil
import boto3
import html
import json
import re
import os




# Function to get the TRS link from the Blockchain
async def getTRSlink(walletDID):
    # Constants
    GENESIS_FILE_PATH = "/home/amineirit/Documents/hyperledger/poolConfig"
    pool = Pool

    # Step 1: Open the pool
    pool = await open_pool(transactions_path=GENESIS_FILE_PATH)

    # Step 2: Query the attribute (GET_ATTRIB)
    get_attrib_request = indyledger.build_get_attrib_request(None, walletDID, "TRSlink", None, None)
    attrib_query_response = await pool.submit_request(get_attrib_request)
    
    # Step 3: Extract the URL from the response
    goal=attrib_query_response['data']
    # Find the start and end positions of the URL
    start_pos = goal.find('"url":"') + len('"url":"')
    end_pos = goal.find('"', start_pos)
            
    # Step 4: Close the pool
    pool.close()

    return goal[start_pos:end_pos]



# Function to extract an OIDC token from a wished CSP
def extract_Token_from_json(json_str, key):
    try:
        # Parse the JSON string into a dictionary
        data = json.loads(json_str)
        
        # Return the value associated with the key, if it exists
        return data.get(key, None)
    except json.JSONDecodeError:
        print("Error decoding JSON")
        return None


# Function to extract the list of vetted OIDC tokens
def extract_csp_list_from_token(access_token):
    try:
        # Split the token into parts (Header, Payload, Signature)
        header, payload, signature = access_token.split('.')

        # Decode the payload from base64
        # Add padding to the payload if necessary
        payload += '=' * (-len(payload) % 4)
        decoded_payload = base64.urlsafe_b64decode(payload).decode('utf-8')

        # Parse the payload as a JSON object
        payload_dict = json.loads(decoded_payload)

        # Extract the "cspList" value
        csp_list = payload_dict.get("cspList", None)
        return csp_list
    except Exception as e:
        print(f"Error decoding token: {e}")
        return None


def get_oidc_token_for_wallet_pkce(keycloak_url, client_id, redirect_uri):
    try: 
        # Generate code verifier and code challenge for PKCE
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
        code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)
        print(f"{Fore.YELLOW}CODE VERIFIER :{Style.RESET_ALL}")
        print(code_verifier)
        
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.replace('=', '')
        print(f"{Fore.YELLOW}CODE CHALLENGE :{Style.RESET_ALL}")
        print(code_challenge)

        # Authentication parameters for PKCE flow
        auth_params = {
            'state': 'crosscloud',
            'scope': 'openid', #In order to get access_token and id_token
            'client_id': client_id,
            'response_type': 'code',
            'redirect_uri': redirect_uri,
            'code_challenge_method': 'S256',
            'code_challenge': code_challenge,
        }

        # Request authorization code from Keycloak
        auth_response = requests.get(f'{keycloak_url}/protocol/openid-connect/auth', params=auth_params, allow_redirects=False)
        if auth_response.status_code != 200:
            print(f"{Fore.RED}STATUS CODE :{Style.RESET_ALL}" + str(auth_response.status_code))
            auth_response.raise_for_status()  # Raises an exception if the response status is 4xx, 5xx
            exit()
        print(f"{Fore.GREEN}STATUS CODE :{Style.RESET_ALL}" + str(auth_response.status_code))
        
        # Parse authorization code from response URL
        cookie = auth_response.headers['Set-Cookie']
        cookie = '; '.join(c.split(';')[0] for c in cookie.split(', '))
        print(f"{Fore.YELLOW}COOKIE :{Style.RESET_ALL}")
        print(cookie)
        
        page = auth_response.text
        form_action = html.unescape(re.search('<form\s+.*?\s+action="(.*?)"', page, re.DOTALL).group(1))
        print(f"{Fore.YELLOW}FORM ACTION :{Style.RESET_ALL}" + form_action)
        #exit()
        
        # Request authorization code from Keycloak
        login_data = {
            "username": "XXX-ommitted-XXX",
            "password": "XXX-ommitted-XXX",
        }
        
        login_response = requests.post(form_action, data=login_data, headers={"Cookie": cookie}, allow_redirects=False)
        if login_response.status_code != 302:
            print(f"{Fore.RED}STATUS CODE :{Style.RESET_ALL}" + str(login_response.status_code))
            auth_response.raise_for_status()  # Raises an exception if the response status is 4xx, 5xx
            exit()
        print(f"{Fore.GREEN}STATUS CODE :{Style.RESET_ALL}" + str(login_response.status_code))
        print(f"{Fore.GREEN}LOGIN resp headers :{Style.RESET_ALL}")
        print(login_response.headers)
        
        redirect = login_response.headers['Location']
        print(f"{Fore.YELLOW}Redirect :{Style.RESET_ALL}" + redirect)
        
        assert redirect.startswith(redirect_uri)
        query = urllib.parse.urlparse(redirect).query
        redirect_params = urllib.parse.parse_qs(query)
        
        auth_code = redirect_params['code'][0]
        print(f"{Fore.YELLOW}Auth code :{Style.RESET_ALL}")
        print(auth_code)
        
        data_access={
            "state": 'crosscloud',
            "code": auth_code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "grant_type": "authorization_code"
        }
        
        token_response = requests.post(f'{keycloak_url}/protocol/openid-connect/token', data=data_access, allow_redirects=False)
        if token_response.status_code != 200:
            print(f"{Fore.RED}Token resp STATUS CODE :{Style.RESET_ALL} " + str(token_response.status_code))
            token_response.raise_for_status()  # Raises an exception if the response status is 4xx, 5xx
            exit()
        print(f"{Fore.GREEN}Token resp STATUS CODE :{Style.RESET_ALL} " + str(token_response.status_code))
        #exit()
        
        return token_response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error during request: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        print("Finished attempting to get OIDC token.")


# Function to download the OIDC tokens from the token retrieval service
def get_tokens_from_trs(keycloak_url, client_id, api_url):
    # Step 1: Get OIDC tokens from Keycloak
    token_response = get_oidc_token_for_wallet_pkce(keycloak_url, client_id)

    if token_response.status_code == 200:
       
       # Extract the access token
        access_token = token_response.json().get('access_token')
        clientList = input("choose OIDC clients from this list "+extract_csp_list_from_token(access_token)+" : ")
        api_url += clientList
        print(api_url)
        
        # Step 2: Use the access token to access the REST API
        api_response = session.get(
            api_url,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if api_response.status_code == 200:
            # Successfully accessed the REST API
            return api_response.json()
        else:
            return f"Failed to access the API: {api_response.status_code}"
    else:
        return f"Failed to obtain access token: {token_response.status_code}"
    

    
# Function to download a file from Google Cloud Storage
def download_file_gcp(bucket_name, source_blob_name, destination_file_name):

    with open('tokenGCP.txt', 'w') as f:
            f.write(extract_Token_from_json(credentials, "gcp"))  # Write the token to a file

    try:
        # Retrieve the token  and exchange it for Google short lived credentials.
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = '/home/amineirit/Documents/owncloud_oidc/clientLibraryConfig-sieramulticloudoidc.json'
        storage_client = storage.Client(project='smiling-matrix-XXXXXX')  # Create a storage client
        
        bucket = storage_client.get_bucket(bucket_name)  # Get the bucket
        blob = bucket.blob(source_blob_name)  # Get the blob
        blob.download_to_filename(destination_file_name)  # Download the blob to a file
        print(f"{Fore.GREEN}File {file_destination} successfully downloaded from GOOGLE CLOUD.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error downloading file from Google Cloud Storage.{Style.RESET_ALL}")  # Print error message if there's an error
        print(f"{e}")



# Function to download a file from Amazon Web Services
def download_file_aws(JWToken):
    cognito = boto3.client('cognito-identity', region_name=aws_region)
    
    # Getting Cognito Identity ID
    response = cognito.get_id( IdentityPoolId=cognito_identity_pool_id,
        Logins={'XXX-ommited_IDP_URL-XXX' : JWToken}
    )


    # Getting Cognito Credentials
    identity_id = cognito.get_credentials_for_identity(IdentityId=response['IdentityId'], 
                                                       Logins={'XXX-ommited_IDP_URL-XXX' : JWToken})
    credentials = identity_id.get('Credentials')
    try:
        # Creating an S3 client with the obtained credentials
        s3 = boto3.client('s3', aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretKey'],
                        aws_session_token=credentials['SessionToken'], region_name=aws_region)

        # Downloading the file
        s3.download_file(s3_bucket_name, file_name, file_destination)
        print(f"{Fore.YELLOW}File '{file_destination}' successfully downloaded from AWS S3.{Style.RESET_ALL}")
    except botocore.exceptions.BotoCoreError as e:
        print(f"Failed to download file '{file_name}' from AWS S3: {e}")
    except botocore.exceptions.ClientError as e:
        print(f"Client error while downloading file '{file_name}' from AWS S3: {e}")



# Function to download a file from OwnCloud
def download_file_oc(access_token,file_url_oc):
    # Get OwnCloud OIDC Token
    access_token = extract_Token_from_json(credentials, "OwnCloudOIDC")

    # Login to ownCloud
    api_response = session.get(
        file_url_oc,
        headers={"Authorization": f"Bearer {access_token}"},
        stream=True
    )

    if api_response.status_code == 200:
        # print(api_response.json())
        # Successfully accessed the REST API
        with open(file_destination, 'wb') as out_file:
            shutil.copyfileobj(api_response.raw, out_file)
        print(f"{Fore.BLUE}File '{file_destination}' successfully downloaded.{Style.RESET_ALL}")
    else:
        return f"Failed to access the API: {api_response.status_code}"
    



# Example usage

#Interactive input
walletdid = input("Enter XCID Wallet DID : ")
file_name = input("Enter the file name : ")

#DID Conf
walletdid = "PmcZnMkFuH14ckZ6WUVxuD"
api_url = asyncio.run(getTRSlink(walletdid))
print(api_url)

# Initialize a session object
session = requests.Session()
keycloak_url = "https://XXX-ommited_IDP_URL-XXX"
client_id = "trsClient"
# File name in the S3 bucket
file_name = 'sujet.pdf'
file_destination = '[' + os.path.splitext(os.path.basename(__file__))[0] + ']' + file_name

#AWS Configuration
aws_region = 'eu-west-3'   # AWS Region
cognito_identity_pool_id = 'eu-west-3:XXX-ommited_pool_id-XXX' # Cognito Identity Pool ID
s3_bucket_name = 'bucketucv1'  # S3 Bucket Name

# Google Cloud Storage Configuration
bucket_name = 'bucketucv1'  # Name of the bucket in Google Cloud Storage # OMMITED FOR CONFIDENTIALITY
file_name = 'sujet.pdf'  # Name of the file in Google Cloud Storage
file_destination = f"[{os.path.splitext(os.path.basename(__file__))[0]}]{file_name}"  # Destination of the file to be downloaded

# OwnCloud Configuration
oc_webdav_url = 'http://172.17.0.3:8080/owncloud/remote.php/webdav/'
oc_file_path = 'Documents/sujet.pdf'
file_full_url = f"{oc_webdav_url}{oc_file_path}"
oc_file_destination = f"OC_{file_name}"  # Destination of the file to be downloaded



# Call the function
credentials = get_tokens_from_trs(keycloak_url, client_id, api_url)
download_file_gcp(bucket_name, file_name, file_destination)
download_file_aws(extract_Token_from_json(credentials, "cognitoS3"))
access_token = extract_Token_from_json(credentials, "OwnCloudOIDC")
download_file_oc(access_token, file_full_url)
