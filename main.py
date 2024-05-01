
from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, request, url_for

import sqlalchemy

from connect_connector import connect_with_connector
# NEED TO DO:   CITATIONS 
# EVERYTHING IS ADAPTED FROM MODULE 5 'Lodgings' Example

BUSINESSES = 'businesses'
ERROR_NOT_FOUND = {'Error' : 'No businesses with this id exists'}
MAX_PAGES = 3

app = Flask(__name__)

logger = logging.getLogger()

# Sets up connection pool for the app
def init_connection_pool() -> sqlalchemy.engine.base.Engine:
    if os.environ.get('INSTANCE_CONNECTION_NAME'):
        return connect_with_connector()
        
    raise ValueError(
        'Missing database connection type. Please define INSTANCE_CONNECTION_NAME'
    )

# This global variable is declared with a value of `None`
db = None

# Initiates connection to database
def init_db():
    global db
    db = init_connection_pool()

# create 'business' table in database if it does not already exist
def create_table_businesses(db: sqlalchemy.engine.base.Engine) -> None:
    # Using a with statement ensures that the connection is always released
    # back into the pool at the end of statement (even if an error occurs)
    with db.connect() as conn:
        # connection.execute() automatically starts a transaction
        ## -- EB ADDED ---------------------------
        # connection.execute() automatically starts a transaction
        # create review 
        conn.execute(
            sqlalchemy.text(
                'CREATE TABLE IF NOT EXISTS businesses ('
                'id SERIAL NOT NULL, '     
                'owner_id INTEGER NOT NULL, '
                'name VARCHAR(255) NOT NULL, '
                'street_address VARCHAR(255) NOT NULL, '
                'city VARCHAR(255) NOT NULL, '
                'state CHAR(2) NOT NULL, '
                'zip_code INTEGER NOT NULL, '
                #'CONSTRAINT zip_code CHECK (zip_code >= 10000 AND zip_code <= 99999)' # this is to ensure zip code is 5 digits, not sure if validation required needed?
                'PRIMARY KEY (id) );'
            )
        )

        # sqlalchem text for 'Reviews' table creation:
        """
        sqlalchemy.text(
            'CREATE TABLE IF NOT EXISTS reviews '
            '(review_id SERIAL NOT NULL, '
            'user_id INTEGER NOT NULL, '
            'business_id INTEGER NOT NULL, '
            'stars INTEGER NOT NULL CHECK (stars >= 0 AND stars <= 5), '
            'review_text TEXT,'
            'CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES users(id), '
            'CONSTRAINT fk_business_id FOREIGN KEY (business_id) REFERENCES businesses(id) '
            'PRIMARY KEY (review_id) );'
        )
        """
        # ---------------------------------------
        
        conn.commit()
        


@app.route('/')
def index():
    return 'Please navigate to /businesses to use this API'

# Create a business
@app.route('/' + BUSINESSES, methods=['POST'])
def post_businesses():
    content = request.get_json()

    # check for required 'Request' parameters?
    # check/validate that required properties are present in json request body
    required_properties = ['owner_id', 'name', 'street_address', 'city', 'state', 'zip_code']
    missing_properties = [prop for prop in required_properties if prop not in content]
    if missing_properties:
        # Return a 400 error response with an error message for missing properties
        error_msg = {"Error":  "The request body is missing at least one of the required attributes"}
        return (error_msg, 400)

    try:
        # Using a with statement ensures that the connection is always released
        # back into the pool at the end of statement (even if an error occurs)
        with db.connect() as conn:
            # Preparing a statement before hand can help protect against injections.
            # NOTICE: :name, :price, etc are BIND variables...
            stmt = sqlalchemy.text(
                'INSERT INTO businesses(owner_id, name, street_address, city, state, zip_code) '
                ' VALUES (:owner_id, :name, :street_address, :city, :state, :zip_code)'
            )
            # connection.execute() automatically starts a transaction
            # Define the :bind variables
            conn.execute(stmt, parameters={'owner_id': content['owner_id'], 
                                        'name': content['name'],
                                        'street_address': content['street_address'],
                                        'city': content['city'],
                                        'state': content['state'],
                                        'zip_code': content['zip_code']})
            # The function last_insert_id() returns the most recent value
            # generated for an `AUTO_INCREMENT` column when the INSERT 
            # statement is executed
            stmt2 = sqlalchemy.text('SELECT last_insert_id()')
            # scalar() returns the first column of the first row or None if there are no rows
            business_id = conn.execute(stmt2).scalar()
            # Remember to commit the transaction
            conn.commit()

    except Exception as e:
        logger.exception(e)
        return ({'Error': 'Unable to create lodging'}, 400)

    # Create HATEOAS response
    response_data = {
        'id': business_id,
        'owner_id': content['owner_id'], 
        'name': content['name'],
        'street_address': content['street_address'],
        'city': content['city'],
        'state': content['state'],
        'zip_code': content['zip_code'],
        'self': url_for('get_business', business_id=business_id, _external=True)  # Generating self link
    }

    # Return the response with status 201 Created
    return (response_data, 201)

# Get all businesses - has pagination implemented
@app.route('/' + BUSINESSES, methods=['GET'])
def get_businesses():
    with db.connect() as conn:

        # Check for filters in query - if they exist
        query_params = request.args
        if ('offset' in query_params):
            offset = int(query_params['offset'])
            limit = int(query_params['limit'])
        else:
            offset = 0      # default parmeters
            limit = 3


        """
        # Create stmt text depending on Offset or Limit prescense
        sql_stmt_start = 'SELECT business_id, owner_id, name, street_address, city, state, zip_code FROM businesses ORDER BY business_id DESC'
        if offset is not None:
            sql_stmt = sqlalchemy.text(sql_stmt_start + ' OFFSET :offset ROWS FETCH NEXT :limit ROWS ONLY')
        else:
            sql_stmt = sqlalchemy.text(sql_stmt_start)
        print(sql_stmt)
        """

        # SQL query with OFFSET and FETCH NEXT clauses for pagination
        sql_stmt = sqlalchemy.text(
            f'SELECT id, owner_id, name, street_address, city, state, zip_code FROM businesses '
            f'ORDER BY id ASC '
            f'LIMIT {offset}, {limit}'
        )

        businesses = []
        rows = conn.execute(sql_stmt)
        # Iterate through the result
        for row in rows:
            # Turn row into a dictionary
            business = row._asdict()   # convert to dict
            
            # Adding the "self" property to each business
            business['self'] = url_for('get_business', business_id=business['id'], _external=True)
            # business['self'] = f"http://104.198.173.141:8000/businesses/{business['business_id']}"

            businesses.append(business)

        # Constructing the response JSON with "entries" and "next" properties
        response_data = {
            "entries": businesses,
            "next": url_for('get_businesses', offset=offset + limit, limit=limit, _external=True) if offset is not None else None
            # "next": f"http://104.198.173.141:8000/businesses?offset={offset + limit}&limit={limit}"

        }

        print((response_data))
        return (response_data)

# Get ALL Businesses - DOESN"T WORK!
@app.route('/' + BUSINESSES + '/<int:business_id>', methods=['GET'])
def get_business(business_id):
    with db.connect() as conn:
        stmt = sqlalchemy.text(
                # Searches with/by primary key
                'SELECT id, owner_id, name, street_address, city, state, zip_code FROM businesses WHERE id = :business_id'
            )
        # one_or_none returns at most one result or raise an exception.
        # returns None if the result has no rows.
        row = conn.execute(stmt, parameters={'business_id': business_id}).one_or_none()
        if row is None:
            return {"Error":  "No business with this business_id exists"  }, 404
        else:
           # Convert the result row to a dictionary
            business = row._asdict()

            # Rename the 'business_id' key to 'id'
            #business['id'] = business.pop('business_id')

            # Create HATEOAS 'self' property - append HATEOAS 'link' info
            business['self'] = url_for('get_business', business_id=business_id, _external=True)
            
            print(business)
            # Return the business data along with the HATEOAS link
            return business

# Update a lodging
@app.route('/' + BUSINESSES + '/<int:business_id>', methods=['PUT'])
def put_business(business_id):
     
     content = request.get_json()

     with db.connect() as conn:
        stmt = sqlalchemy.text(
            # Searches with/by primary key - business_id
                'SELECT id, owner_id, name, street_address, city, state, zip_code FROM businesses WHERE id=:business_id'
            )
        row = conn.execute(stmt, parameters={'business_id': business_id}).one_or_none()
        if row is None:
            return {"Error":  "No business with this business_id exists"} , 404
        

        else:

            # check for required 'Request' parameters?
            required_properties = ['owner_id', 'name', 'street_address', 'city', 'state', 'zip_code']
            missing_properties = [prop for prop in required_properties if prop not in content]
            if missing_properties:
                # Return a 400 error response with an error message for missing properties
                error_msg = {"Error":  "The request body is missing at least one of the required attributes"}
                return (error_msg, 400)
            
            stmt = sqlalchemy.text(
                # update statement
                'UPDATE businesses SET owner_id = :owner_id, name = :name, street_address = :street_address, city = :city, state = :state, zip_code = :zip_code WHERE id = :business_id'
            )

            # replaces with request JSON body paramters name, etc.
            # NOTICE: business_id doesn't use JSON Body           
            conn.execute(stmt, parameters={'business_id': business_id,
                                           'owner_id': content['owner_id'], 
                                           'name': content['name'],
                                           'street_address': content['street_address'],
                                           'city': content['city'],
                                           'state': content['state'],
                                           'zip_code': content['zip_code']})


            conn.commit() # always commit 

            return {'id': business_id,
                    'owner_id': content['owner_id'], 
                    'name': content['name'],
                    'street_address': content['street_address'],
                    'city': content['city'],
                    'state': content['state'],
                    'zip_code': content['zip_code'],
                    'self': url_for('get_business', business_id=business_id, _external=True)}  # add self HATEOAS link

# Delete a lodging
@app.route('/' + BUSINESSES + '/<int:business_id>', methods=['DELETE'])
def delete_business(business_id):
     
     with db.connect() as conn:
        stmt = sqlalchemy.text(
                'DELETE FROM businesses WHERE id=:business_id'
            )

        result = conn.execute(stmt, parameters={'business_id': business_id}) # 'result' has a inherit 'rowcount' property due to sqlalchemy
        conn.commit()
        # result.rowcount value will be the number of rows deleted - int. type
        # For our statement, the value be 0 or 1 because lodging_id is
        # the PRIMARY KEY
        if result.rowcount == 1:
            return ('', 204)
        else:
            return {"Error":  "No business with this business_id exists"} , 404



#----------------------------------------------------------------------
#------------------------- REVIEWS-------------------------------------  
#----------------------------------------------------------------------
REVIEWS = 'reviews'

# NOT DONE YET!

# create 'business' table in database if it does not already exist
def create_table_reviews(db: sqlalchemy.engine.base.Engine) -> None:
    # Using a with statement ensures that the connection is always released
    # back into the pool at the end of statement (even if an error occurs)
    with db.connect() as conn:
        # connection.execute() automatically starts a transaction
        ## -- EB ADDED ---------------------------
        # connection.execute() automatically starts a transaction
        # create review 
        conn.execute(
            sqlalchemy.text(
                'CREATE TABLE IF NOT EXISTS businesses ('
                'business_id SERIAL NOT NULL, '     
                'owner_id INTEGER NOT NULL, '
                'name VARCHAR(255) NOT NULL, '
                'street_address VARCHAR(255) NOT NULL, '
                'city VARCHAR(255) NOT NULL, '
                'state CHAR(2) NOT NULL, '
                'zip_code INTEGER NOT NULL, '
                #'CONSTRAINT zip_code CHECK (zip_code >= 10000 AND zip_code <= 99999)' # this is to ensure zip code is 5 digits, not sure if validation required needed?
                'PRIMARY KEY (business_id) );'
            )
        )

        # sqlalchem text for 'Reviews' table creation:
        """
        sqlalchemy.text(
            'CREATE TABLE IF NOT EXISTS reviews '
            '(review_id SERIAL NOT NULL, '
            'user_id INTEGER NOT NULL, '
            'business_id INTEGER NOT NULL, '
            'stars INTEGER NOT NULL CHECK (stars >= 0 AND stars <= 5), '
            'review_text TEXT,'
            'CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES users(id), '
            'CONSTRAINT fk_business_id FOREIGN KEY (business_id) REFERENCES businesses(id) '
            'PRIMARY KEY (review_id) );'
        )
        """
        # ---------------------------------------
        
        conn.commit()
        

# Create a review
@app.route('/' + REVIEWS, methods=['POST'])
def post_reviews():
    content = request.get_json()

    # check for required 'Request' parameters?
    # check/validate that required properties are present in json request body
    required_properties = ['owner_id', 'name', 'street_address', 'city', 'state', 'zip_code']
    missing_properties = [prop for prop in required_properties if prop not in content]
    if missing_properties:
        # Return a 400 error response with an error message for missing properties
        error_msg = {"Error":  "The request body is missing at least one of the required attributes"}
        return (error_msg, 400)

    try:
        # Using a with statement ensures that the connection is always released
        # back into the pool at the end of statement (even if an error occurs)
        with db.connect() as conn:
            # Preparing a statement before hand can help protect against injections.
            # NOTICE: :name, :price, etc are BIND variables...
            stmt = sqlalchemy.text(
                'INSERT INTO businesses(owner_id, name, street_address, city, state, zip_code) '
                ' VALUES (:owner_id, :name, :street_address, :city, :state, :zip_code)'
            )
            # connection.execute() automatically starts a transaction
            # Define the :bind variables
            conn.execute(stmt, parameters={'owner_id': content['owner_id'], 
                                        'name': content['name'],
                                        'street_address': content['street_address'],
                                        'city': content['city'],
                                        'state': content['state'],
                                        'zip_code': content['zip_code']})
            # The function last_insert_id() returns the most recent value
            # generated for an `AUTO_INCREMENT` column when the INSERT 
            # statement is executed
            stmt2 = sqlalchemy.text('SELECT last_insert_id()')
            # scalar() returns the first column of the first row or None if there are no rows
            business_id = conn.execute(stmt2).scalar()
            # Remember to commit the transaction
            conn.commit()

    except Exception as e:
        logger.exception(e)
        return ({'Error': 'Unable to create lodging'}, 400)

    # Create HATEOAS response
    response_data = {
        'id': business_id,
        'owner_id': content['owner_id'], 
        'name': content['name'],
        'street_address': content['street_address'],
        'city': content['city'],
        'state': content['state'],
        'zip_code': content['zip_code'],
        'self': url_for('get_business', business_id=business_id, _external=True)  # Generating self link
    }

    # Return the response with status 201 Created
    return (response_data, 201)

            

if __name__ == '__main__':
    init_db()
    create_table_businesses(db)
    app.run(host='0.0.0.0', port=8080, debug=True)
