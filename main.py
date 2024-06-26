
from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, request, url_for

import sqlalchemy

from connect_connector import connect_with_connector
# NEED TO DO:   CITATIONS 
# EVERYTHING IS ADAPTED FROM MODULE 5 'Lodgings' Example

BUSINESSES = 'businesses'
OWNERS = "owners"
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
def create_tables(db: sqlalchemy.engine.base.Engine) -> None:
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
                'name VARCHAR(50) NOT NULL, '
                'street_address VARCHAR(100) NOT NULL, '
                'city VARCHAR(50) NOT NULL, '
                'state CHAR(2) NOT NULL, '
                'zip_code INTEGER NOT NULL CHECK (zip_code >= 10000 AND zip_code <= 99999), '
                'PRIMARY KEY (id) );'
            )
        )

        # create review 
        conn.execute(
            sqlalchemy.text(
            'CREATE TABLE IF NOT EXISTS reviews ( '
            'id SERIAL NOT NULL, '
            'user_id INTEGER NOT NULL, '
            'business_id INTEGER NOT NULL, '
            'stars INTEGER NOT NULL CHECK (stars >= 0 AND stars <= 5), '
            'review_text VARCHAR(1000), ' 
            'PRIMARY KEY (id) );'
            )
        )
            
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

        #print((response_data))
        return (response_data)

# Get ALL Businesses 
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

# Get All busineses by OWNER
#@app.route('/' + OWNERS + '/<int:owner_id>/businesses', methods=['GET'])
@app.route('/owners/<int:owner_id>/businesses', methods=['GET'])
def get_businesses_by_owner(owner_id):
    with db.connect() as conn:
        stmt = sqlalchemy.text(
            'SELECT id, owner_id, name, street_address, city, state, zip_code FROM businesses WHERE owner_id = :owner_id'
        )
        rows = conn.execute(stmt, parameters={'owner_id': owner_id})

        # returns list of each business dict 
        businesses = [row._asdict() for row in rows]

        # check if None found 
        if not businesses:
            return {"Error": "No businesses found for this owner"}, 404

        # add HATEOAS 'self' link to business 
        for business in businesses:
            business['self'] = url_for('get_business', business_id=business['id'], _external=True)

        #response_data = {
        #    "entries": businesses,
        #    "count": len(businesses)
        #}

        #print(business)
        return businesses


# Update a business
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

# Delete a business
@app.route('/' + BUSINESSES + '/<int:business_id>', methods=['DELETE'])
def delete_business(business_id):
     
     with db.connect() as conn:
        # Delete reviews
        stmt_reviews = sqlalchemy.text(
            "DELETE FROM reviews WHERE business_id = :business_id"
        )
        conn.execute(stmt_reviews, parameters={'business_id': business_id})

        # Delete business
        stmt_business = sqlalchemy.text(
            "DELETE FROM businesses WHERE id = :business_id"
        )
        result = conn.execute(stmt_business, parameters={'business_id': business_id})
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
USERS = 'users'
# NOT DONE YET!

"""
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
            'CREATE TABLE IF NOT EXISTS reviews ( '
            'id SERIAL NOT NULL, '
            'user_id INTEGER NOT NULL, '
            'business_id INTEGER NOT NULL, '
            'stars INTEGER NOT NULL CHECK (stars >= 0 AND stars <= 5), '
            'review_text VARCHAR(1000), ' 
            'PRIMARY KEY (id) );'
            )
        )       
        conn.commit()
"""

# Create a review
@app.route('/' + REVIEWS, methods=['POST'])
def post_reviews():
    content = request.get_json()

    # check for required 'Request' parameters?
    # check/validate that required properties are present in json request body
    required_properties = ['user_id', 'business_id', 'stars']
    missing_properties = [prop for prop in required_properties if prop not in content]
    if missing_properties:
        # Return a 400 error response with an error message for missing properties
        error_msg = {"Error":  "The request body is missing at least one of the required attributes"}
        return (error_msg, 400)
    
    # set 'review_text' check
    if 'review_text' in content :
        review_text = content['review_text']
    else:
        review_text = ""

    # set content variable from request
    user_id = content['user_id']
    business_id = content['business_id']
    stars = content['stars']

    try:
        # Using a with statement ensures that the connection is always released
        # back into the pool at the end of statement (even if an error occurs)
        with db.connect() as conn:

            # Check if the business exists   - NOT SURE IF WORKS?
            stmt = sqlalchemy.text('SELECT id FROM businesses WHERE id = :business_id')
            # returns None if the result has no rows.
            row = conn.execute(stmt, parameters={'business_id': business_id}).one_or_none()
            if row is None:
                return {"Error":  "No business with this business_id exists"}, 404

            
            # IMPLEMENT - check if review_exists already 
            stmt = sqlalchemy.text('SELECT * FROM reviews WHERE user_id = :user_id AND business_id = :business_id')
            row = conn.execute(stmt, parameters={'user_id': user_id, 'business_id': business_id}).one_or_none()
            if row is not None:
                err_msg = {"Error":  "You have already submitted a review for this business. You can update your previous review, or delete it and submit a new review" }
                return err_msg, 409

            # create sqalchemy.text
            sql_stmt = sqlalchemy.text( 'INSERT INTO reviews (user_id, business_id, stars, review_text) '
                                        ' VALUES (:user_id, :business_id, :stars, :review_text)'
            )

            # create parameters
            sql_params = {
                'user_id': user_id, 
                'business_id': business_id,
                'stars': stars,
                'review_text': review_text
            }

            # execute sql_stmt with sql_stmt_parmeters
            conn.execute(sql_stmt, parameters = sql_params)

            stmt2 = sqlalchemy.text('SELECT last_insert_id()')
            # scalar() returns the first column of the first row or None if there are no rows
            primary_id = conn.execute(stmt2).scalar()
            # Remember to commit the transaction
            conn.commit()

    except Exception as e:
        logger.exception(e)
        return ({'Error': 'Unable to create lodging'}, 400)

    # Create HATEOAS response 
    response_data = {
        'id': primary_id,
        'user_id': content['user_id'], 
        'business': url_for('get_business', business_id=business_id, _external=True),
        'stars': content['stars'],
        'review_text': review_text, # couled be empty string ""
        'self': url_for('get_review', review_id=primary_id, _external=True)  # Generating 'self' link
    }

    # Return the response with status 201 Created
    print("\n")
    print(f"RESPONSE DATA ={response_data}")
    return (response_data, 201)

# ----- get review by id -------
@app.route('/' + REVIEWS + '/<int:review_id>', methods=['GET'])
def get_review(review_id):
    with db.connect() as conn:
        stmt = sqlalchemy.text(
                # Searches with/by primary key = id
                'SELECT id, user_id, business_id, stars, review_text FROM reviews WHERE id = :review_id'
            )
        # one_or_none returns at most one result or raise an exception.
        # returns None if the result has no rows.
        row = conn.execute(stmt, parameters={'review_id': review_id}).one_or_none()
        if row is None:
            return {"Error":  "No review with this review_id exists" }, 404
        else:
           # Convert the result row to a dictionary
            review = row._asdict()

            # Extract + remove business_id from the review
            sql_busi_id = review.pop('business_id', None)
            # Creat HATEOAS business link
            review['business'] = url_for('get_business', business_id=sql_busi_id, _external=True)

            # Create HATEOAS 'self' property - append HATEOAS 'link' info
            review['self'] = url_for('get_review', review_id=review_id, _external=True)
            
            print(review)
            # Return the business data along with the HATEOAS link
            return review
  
# ----- edit a review ------ DOESN"T WORK?
@app.route('/' + REVIEWS + '/<int:review_id>', methods=['PUT'])
def put_review(review_id):
     
     content = request.get_json()

     with db.connect() as conn:
        stmt = sqlalchemy.text(
            # Searches with/by primary key - business_id
                'SELECT id, user_id, business_id, stars, review_text FROM reviews WHERE id=:review_id'
            )
        row = conn.execute(stmt, parameters={'review_id': review_id}).one_or_none()
        if row is None:
            return {"Error":  "No review with this review_id exists"} , 404

        else:

            # check for required 'Request' parameters
            required_properties = ['stars']
            missing_properties = [prop for prop in required_properties if prop not in content]
            if missing_properties:
                # Return a 400 error response with an error message for missing properties
                error_msg = {"Error":  "The request body is missing at least one of the required attributes"}
                return (error_msg, 400)          

            # get values from returned sql 'Review'
            returned_review = row._asdict()  # Returned 'Review' info from db - as dict. 
            user_id = returned_review['user_id'] # uses SQL return info 
            business_id = returned_review['business_id']
            stars = content['stars'] # uses request info

            # BUILD sql_stmt + sql_params
            sql_stmt_query = 'UPDATE reviews SET stars = :stars WHERE id = :review_id'
            sql_params = {'review_id': review_id,
                        'user_id': user_id, 
                        'business_id': business_id,
                        'stars': stars}
            
            # add 'review_text' if present
            if 'review_text' in content:
                sql_stmt_query = 'UPDATE reviews SET stars = :stars, review_text = :review_text WHERE id = :review_id'
                sql_params.update({'review_text': content['review_text']}) 

            stmt = sqlalchemy.text(sql_stmt_query)           
            conn.execute(stmt, parameters=sql_params)
            conn.commit() # always commit 

            # -------  Creating the HATEOS link Response -------- 
            # Extract + removes business_id from the review
            sql_busi_id = returned_review.pop('business_id', None)
            # Create HATEOAS business link
            returned_review['business'] = url_for('get_business', business_id=sql_busi_id, _external=True)
            # Create HATEOAS 'self' property - append HATEOAS 'link' info
            returned_review['self'] = url_for('get_review', review_id=review_id, _external=True)
            returned_review['stars'] = stars
            # add 'review_text' if present
            if 'review_text' in content:
                returned_review['review_text'] = content['review_text']

            return returned_review

@app.route('/' + REVIEWS + '/<int:review_id>', methods=['DELETE'])
def delete_review(review_id):
     
     with db.connect() as conn:
        stmt = sqlalchemy.text(
                'DELETE FROM reviews WHERE id=:review_id'
            )

        result = conn.execute(stmt, parameters={'review_id': review_id}) # 'result' has a inherit 'rowcount' property due to sqlalchemy
        conn.commit()
        # result.rowcount value will be the number of rows deleted - int. type
        # For our statement, the value be 0 or 1 because lodging_id is
        # the PRIMARY KEY
        if result.rowcount == 1:
            return ('', 204)
        else:
            return {"Error":  "No review with this review_id exists"}  , 404

@app.route('/' + USERS + '/<int:user_id>/' + REVIEWS, methods=['GET'])
def get_review_by_user(user_id):
    with db.connect() as conn:
        stmt = sqlalchemy.text(
            'SELECT id, user_id, business_id, stars, review_text FROM reviews WHERE user_id = :user_id'
        )
        rows = conn.execute(stmt, parameters={'user_id': user_id})

        # returns list of each business dict 
        reviews_by_user = [row._asdict() for row in rows]

        # add HATEOAS 'self' link to each review entry 
        for rev in reviews_by_user:
            rev['business'] = url_for('get_business', business_id=rev['business_id'], _external=True)
            rev['self'] = url_for('get_review', review_id=rev['id'], _external=True)

        return reviews_by_user, 200

if __name__ == '__main__':
    init_db()
    create_tables(db)
    app.run(host='0.0.0.0', port=8080, debug=True)
