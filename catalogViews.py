#!/usr/bin/env python3
#
# Catalog Project
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy.engine import create_engine
from models import Base, User, Category, Item
from sqlalchemy.orm.session import sessionmaker
from oauth2client.client import flow_from_clientsecrets

# imports to manage login session
from flask import session as login_session
import random, string

# imports for google connect implementation
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import os

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secret_catalog.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Dummy Database for start up
category = {'name': 'Electronics', 'id':'1'}
categories1 = [{'name': 'Electronics', 'id':'1'}, {'name':'Home', 'id':'2'}]
items = [{'name':'Television', 'description':'42 inch LED Display', 'price':'$899.99', 'id':'1', 'category_id':'1'},
         {'name':'Table', 'description':'Teak wood table with smooth finishing', 'price':'$399.99', 'id':'2', 'category_id':'2'}]


@app.route('/')
@app.route('/catalog/')
def show_categories():
    ''' Show categories with Latest Items on the home page'''
    categories = session.query(Category).all()
    return render_template('catalog.html', categories=categories)


@app.route('/catalog/<category_name>/')
@app.route('/catalog/<category_name>/items/')
def show_category_items(category_name):
    print("in the show_category_items :" + category_name)
    category = session.query(Category).filter_by(name=category_name).first()
    if category is not None:
        items = session.query(Item).filter_by(category_id=category.id)
        return render_template('category.html', category=category, items=items)
    else:
        return "No Items to display"  # message flashing 


@app.route('/catalog/<category_name>/<item_name>/')
def  show_item(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).first()
#     print("Showing category " + str(category.id) + ":" + item_name)
    if category is not None:
        item = session.query(Item).filter_by(category_id=category.id, name=item_name).first()
#         print("Item Information " + str(item.id) + ":" + item.description)
        return render_template('item.html', category=category, item=item)
    else:
        return "No Item Info to display"  # message flashing


@app.route('/catalog/<category_name>/<item_name>/edit/', methods=['GET', 'POST'])
def edit_item(category_name, item_name):
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(name=category_name).first()
    if category is not None:
        item = session.query(Item).filter_by(category_id=category.id, name=item_name).first()
    
    if request.method == 'GET':
        return render_template('edit_item.html', categories=categories, item=item)
    else:
        if request.form['submit'] == "Update":
            item.description = request.form['itemName']
            item.category_id = request.form['categoryId']
            updatedCategory = session.query(Category).filter_by(id=item.category_id).one()
            category_name = updatedCategory.name
            session.add(item)
            session.commit()
        return redirect(url_for('show_category_items', category_name=category_name))


@app.route('/catalog/<category_name>/<item_name>/delete/', methods=['GET', 'POST'])
def delete_item(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).first()
    if category is not None:
        item = session.query(Item).filter_by(category_id=category.id, name=item_name).first()
    if request.method == 'GET':
        return render_template('delete_item.html', category=category, item=item)
    else:
        if request.form['submit'] == 'Delete':
            session.delete(item)
            session.commit()
        return redirect(url_for('show_category_items', category_name=category_name))


@app.route('/catalog/<category_name>/items/new/', methods=['GET', 'POST'])
def add_item(category_name):
    if request.method == 'GET':
        categories = session.query(Category).all()
        return render_template('add_item.html', categories=categories)
    else:
        if request.form['submit'] == 'Add':
            category_id = request.form['categoryName']
            # check here for the selected category
            item_name = request.form['itemName']
            item_description = request.form['itemDescription']
            category = session.query(Category).filter_by(id=category_id).one()
            category_name = category.name
            item = Item(name=item_name, description=item_description, category_id=category_id)
            session.add(item)
            session.commit()
        return redirect(url_for('show_category_items', category_name=category_name))


@app.route('/catalog/new/', methods=['GET', 'POST'])
def add_category():
    if request.method == 'GET':
        return render_template('add_category.html')
    else:
        if request.form['submit'] == "Add":
            category_name = request.form['categoryName']
            category = Category(name=category_name)
            session.add(category)
            session.commit()
        return redirect(url_for('show_categories'))


@app.route('/catalog/<category_name>/edit/')
def edit_category(category_name):
    category = {'name': 'Electronics1', 'id':'1'}
    return render_template('edit_category.html', category=category)


@app.route('/catalog/<category_name>/delete/')
def delete_category(category_name):
    category = {'name': 'Electronics', 'id':'1'}
    return render_template('delete_category.html', category=category)


# Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) 
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnectold', methods=['POST'])
def gconnectold():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dump('Invalid state', 401))
        response.headers['Content-Type'] = 'application/json'
        return response
    # if the state matches, then retrieving the one-time code
    code = request.data
    try:
        # Upgrade the authorization code into the credentials object
        flow = flow_from_clientsecrets('client_secret_catalog.json', scope='')
        flow.redirect_uri = 'postmessage'
        credentials = flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps
                                 ('Failed to upgrade the authorization code')
                                 , 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # url = ('https://www.googleapis.com/oauth/v1/tokeninfo?access_token=%s' 
    #      % access_token)
    h = httplib2.Http()
    # ##response, content = h.request(url, 'GET')
    # ##result = json.loads(content)
    result = json.loads(h.request(url, 'GET')[1])
    # If the result i.e. access_token info contains an error, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(""" Token's user id
        doesn't match give user id."""), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this application.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(""" Token's client id
        doesn't match application's id."""), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check to see if the user is already logged in 
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('''Current user is already 
        connected.'''), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # Store the access token in the session for later use.
    login_session['credentials'] = credentials  # TypeError: Object of type 'OAuth2Credentials' is not JSON serializable
    # login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    
    # Get user information
    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)
    
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    # output += '<img src="'
    # output += login_session['picture']
    # output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    # flash("you are now logged in as %s" % login_session['username'])
    print ("Successfully logged in !!!")
    return output    


# Disconnect ; Revoke a current user's token and reset their login_session.
@app.route('/gdisconnectold')
def gdisconnectold():
    # Only disconnect a  connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dump('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute HTTP GET request to revoke current token.
    # access_token = credentials.access_token
    access_token = login_session['credentials']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    
    if result['status'] == '200':
        # Reset the user's session.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('''Failed to revoke 
        token for given user.'''), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

        
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret_catalog.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps('error is here....'), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
#     user_id = getUserID(login_session['email'])
#     print(user_id)
#     if not user_id:
#         user_id = createUser(login_session)    
    
#     login_session['user_id'] = user_id    

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
#     output += '<img src="'
#     output += login_session['picture']
#     output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
#     flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print ('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print ('In gdisconnect access token is %s', access_token)
    print ('User name is: ')
    print (login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print ('result is ')
    print (result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# API Endpoints with JSON
@app.route("/catalog/JSON/")
def show_categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[category.serialize for category in categories])


@app.route('/catalog/<category_name>/items/JSON/')
def show_category_itemsJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).first()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return jsonify(Items=[item.serialize for item in items])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='localhost', port=5002)
