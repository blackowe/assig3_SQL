import io
from flask import Flask, request, jsonify, send_file, url_for
from google.cloud import datastore, storage

import requests
import json

from six.moves.urllib.request import urlopen # type: ignore
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

#client = datastore.Client()
client = datastore.Client(project='assign6-tarpaulin')


USERS = "users"
AVATAR = "avatar"
PHOTO_BUCKET='cs493-assign6-bucket'
ADMIN_SUB = "auth0|664e3772e322ea9ec94bbd87"

# Update the values of the following 3 variables
CLIENT_ID = 'DgnjGz9FWwnahQk83m0WQ7x9gZsTTyrL'
CLIENT_SECRET = '3gbH6s5K1JJx7mtJJzWtatjjRNTkHBcNoAcwulhA8bF4nPU3Exbw_B9TjlGJhge2'
DOMAIN = 'dev-omzcv0p3zbhlb40w.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)



# ------------------------- login_user()  Attempt #1 (passes folder 1 tests)-------------------------------
# This code is adapted from https://canvas.oregonstate.edu/courses/1958154/pages/exploration-implementing-a-rest-api-using-mysql?module_item_id=24110745  main.py
# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token

@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    content = request.get_json()

    # check for 'username' & 'password' in content body
    if 'username' not in content or 'password' not in content:
        return {"Error": "The request body is invalid"}, 400
    
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password',
            'username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = {'content-type': 'application/json'}
    url = f'https://{DOMAIN}/oauth/token'

    # send post request using login info
    r = requests.post(url, json=body, headers=headers)

    if r.status_code != 200:
        return {"Error":"Unauthorized"}, 401

    response_json = r.json()
    token = response_json.get('id_token')
    print({"token": token})

    return jsonify({"token": token}), r.status_code


# This code is adapted from https://canvas.oregonstate.edu/courses/1958154/pages/exploration-implementing-a-rest-api-using-mysql?module_item_id=24110745  main.py
# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload        


@app.route('/')
def index():
    return "CS 493 Assignment 6 - Created By: Erik Blackowicz"

## specify business ID #(primary key), as int
@app.route('/' + USERS + '/<int:id>', methods =['GET'])
def get_user_by_id(id):

    # verify jwt, compare with 
    try:
        payload = verify_jwt(request)
        print(f"PAYLOAD = {payload}")
        
    except AuthError as error:
        return jsonify({"Error": "Unauthorized"}), 401
    
    # get user from db
    user_key = client.key(USERS,id)      # create unique business key
    db_user = client.get(key = user_key)     # search for existing BUSINESSES key, returns business ENTITY, else return None
    db_user_sub = db_user.get('sub')

    if not db_user:
        return jsonify({"Error": "User does not exist"}), 403

    if db_user.get('role')!= 'admin' and (payload.get('sub') != db_user.get('sub')):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Construct the response
    response_user = {
        'id': db_user.key.id,
        'role': db_user.get('role'),
        'sub': db_user.get('sub')
    }
    # Add avatar_url if exists
    if 'avatar_url' in db_user:
        response_user['avatar_url'] = db_user['avatar_url']

    # Add courses if the user is an instructor or student
    if db_user['role'] in ['instructor', 'student']:
        response_user['courses'] = db_user.get('courses', [])
    
    return jsonify(response_user), 200

@app.route('/' + USERS + '/<int:id>/' + AVATAR, methods =['GET'])
def get_user_avatar(id):

    # verify jwt, compare with 
    try:
        payload = verify_jwt(request)
        print(f"PAYLOAD = {payload}")
        
    except AuthError as error:
        return jsonify({"Error": "Unauthorized"}), 401
    
    # get user from db based on input id
    user_key = client.key(USERS,id)      # create unique business key
    db_user = client.get(key = user_key)     # search for existing BUSINESSES key, returns business ENTITY, else return None
    db_user_sub = db_user.get('sub')
    
    # 403 error handle - JWT is valid, but user_id mismatch
    if payload.get('sub') != db_user.get('sub'):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # 404 error handle - User doesn't have avatar in GC Storage
    if 'avatar_url' not in db_user:
        return jsonify({"Error": "Not found"}), 404
    
    # Get the file_name from the avatar_url
    file_name = db_user['filename']
    print(f"\nFILE NAME = {file_name}\n")

    # ------- CITE: M8 lecture main.py 'get_image' -------------
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob with the given file name
    blob = bucket.blob(file_name)
    # Create a file object in memory using Python io package
    file_obj = io.BytesIO()
    # Download the file from Cloud Storage to the file_obj variable
    blob.download_to_file(file_obj)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Send the object as a file in the response with the correct MIME type and file name
    return send_file(file_obj, mimetype='image/x-png', download_name=file_name)
    #-----------------------------------------------------------------------



@app.route('/' + USERS, methods =['GET'])
def list_all_users():
   
    try:
        payload = verify_jwt(request)
    except AuthError:
        return jsonify({"Error": "Unauthorized"}), 401

    if payload.get('sub')!= ADMIN_SUB:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    ## Will Query the Datastore and return stored Entities 'id','role','sub' info only
    query = client.query(kind=USERS)
    results = list(query.fetch())
    response_list = []
    for entity in results:
        entity_prop = {
            'id': entity.key.id,   #  don't keep ID in datastore
            'role': entity.get('role'),
            'sub': entity.get('sub')
        }
        response_list.append(entity_prop)
    return jsonify(response_list), 200

# CITE: m8-main.py 'store_image()' fx
# Create a business if the Authorization header contains a valid JWT
@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['POST'])
def create_update_avatar(user_id):
    # no 'file' in request - 400 handle
    if 'file' not in request.files:
        return jsonify({"Error": "The request body is invalid"}), 400
    
    # verify jwt - 401 handle
    try:
        payload = verify_jwt(request)
        print(f'PAYLOAD = {payload}')
    except AuthError as error:
        return jsonify({"Error": "Unauthorized"}), 401

    # get user from db
    user_key = client.key(USERS,user_id)
    db_user = client.get(key = user_key)
    print(f'DB_USER = {db_user}')

    # If user does not exist, return 403
    #if not db_user:
    #    return jsonify({"Error": "You don't have permission on this resource"}), 403

    # verify user_id is the same as db_user_id
    if payload.get('sub') != db_user.get('sub'):
        return jsonify({"Error": "You don't have permission on this resource"}), 403


    # create avatar url
    avatar_url = url_for('get_user_by_id', id = user_id, _external=True) +'/avatar'
    # create response
    response = {'avatar_url': avatar_url}

    # ----- set avatar .png in google Cloud storage---
    #TODO: Fix how to store filename of avatar / use avatar_url
    # set file object relating to file.png
    file_obj = request.files['file']
    #print(f'FILE_Obj = {file_obj.filename}')

    # add avatar_url to datastore entity 
    db_user['avatar_url'] = avatar_url
    entity_to_be_updated = datastore.Entity(key = user_key)
    entity_to_be_updated.update({
        'sub' : db_user['sub'],
        'role' : db_user['role'],
        'filename': file_obj.filename,
        'avatar_url': avatar_url
    })

    if 'courses' in entity_to_be_updated:
        entity_to_be_updated['courses'] = db_user['courses']
    client.put(entity_to_be_updated)
    

    # ----- set avatar .png in google Cloud storage---
    # set file object relating to file.png
    #file_obj = request.files['file']
    #print(f'FILE_Obj = {file_obj.filename}')

    # Create a storage client
    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob object for the bucket with the name of the file
    blob = bucket.blob(file_obj.filename)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Upload the file into Cloud Storage
    blob.upload_from_file(file_obj)

    return (response,200)

# CITE: M8 - main.py 'delete_image' 
@app.route('/' + USERS + '/<int:id>/' + AVATAR, methods=['DELETE'])
def delete_image(id):
    # 401 error handle - verify jwt, compare with 
    try:
        payload = verify_jwt(request)
        print(f"PAYLOAD = {payload}")
    except AuthError as error:
        return jsonify({"Error": "Unauthorized"}), 401
    
    # 403 error handle - The JWT is valid but doesn’t belong to the user whose ID is in the path parameter. 
    # get user from db
    user_key = client.key(USERS,id)      
    db_user = client.get(key = user_key)     
    # verify user_id is the same as db_user_id
    if payload.get('sub') != db_user.get('sub'):
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    
    # 404 error handle - User doesn't have avatar in GC Storage
    if 'avatar_url' not in db_user:
        print("avatar_url not found in db_user")
        return jsonify({"Error": "Not found"}), 404


    # 204 - delete avatar
    file_name = db_user.get('filename')
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_name)
    blob.delete()

    # update - db_user's 'avatar_url' by deleting the property
    del db_user['avatar_url']
    del db_user['filename']  # Assuming you also want to delete the filename property
    client.put(db_user)

    return '',204


# ADDED POST Courses route:--------------------------------------------------------
COURSES = "courses"

@app.route('/' + COURSES, methods=['POST'])
def create_course():
    
    # 401 error handle
    try:
        payload = verify_jwt(request)
    except AuthError as error:
        return jsonify({"Error": "Unauthorized"}), 401
        
    # 403 eror handle:
     if payload.get('sub')!= ADMIN_SUB:
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    
    # 400 error handle 
    # verify all required properties present
    required_properites = ['subject', 'number', 'title', 'term', 'instructor_id']
    missing_properties = [prop for prop in required_properties if prop not in content]
    if missing_properties:
        error_msg = {"Error":  "The request body is missing at least one of the required attributes"}
        return (error_msg, 400)
    
    # 400 error handle - verify instructor_id is real
    content = request.get_json()
    instruct_id = content.get('instructor_id')
    user_key = client.key(USERS,instructor_id)      
    instructor = client.get(key = user_key)
    if not db_user:
        return jsonify({"Error": "User does not exist"}), 400
    
    # 
    entity_to_be_added = datastore.Entity(key = user_key)
    entity_to_be_updated.update({
        'sub' : db_user['sub'],
        'role' : db_user['role'],
        'filename': file_obj.filename,
        'avatar_url': avatar_url
    })
    



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

