#!/usr/bin/env python3
#
# Catalog Project: Its like an ecommerce website which provides us
# with the ability to add different categories and different items
# within those categories.
from flask import Flask, render_template, request, redirect, jsonify
from flask import url_for, flash
from sqlalchemy.engine import create_engine
from models import Base, User, Category, Item
from sqlalchemy.orm.session import sessionmaker
from oauth2client.client import flow_from_clientsecrets

# imports to manage login session
from flask import session as login_session
import random
import string

# imports for google connect implementation
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import os
from gettext import Catalog

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secret_catalog.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/catalog/')
def show_categories():
    ''' Show categories with Latest Items on the home page'''
    try:
        categories = session.query(Category).all()
        # Latest 5 items are being displayed i.e. order by item.id desc
        latestItems = session.query(Item.name.label('itemName'),
                                    Category.name.label('categoryName')
                                    ).filter(Item.category_id == Category.id
                                             ).order_by(Item.id.desc()
                                                        ).limit(5)
    except:
        print("show_categories: Exception communicating with the database.")
    if 'username' not in login_session or 'username' is None:
        return render_template('public_catalog.html',
                               categories=categories, latestItems=latestItems)
    else:
        return render_template('catalog.html',
                               categories=categories, latestItems=latestItems)


@app.route('/catalog/<category_name>/')
@app.route('/catalog/<category_name>/items/')
def show_category_items(category_name):
    ''' Show all the items of the specified category'''
    try:
        category = session.query(Category).filter_by(
            name=category_name).first()
        categories = session.query(Category).all()
        if category is not None:
            items = session.query(Item).filter_by(category_id=category.id)
            if 'username' not in login_session:
                return render_template('public_category.html',
                                       category=category, items=items,
                                       categories=categories)
            else:
                return render_template('category.html',
                                       category=category, items=items,
                                       categories=categories)
        else:
            return "No Items to display"
    except:
        print("""show_category_items:
         Exception communicating with the database.""")


@app.route('/catalog/<category_name>/<item_name>/')
def show_item(category_name, item_name):
    ''' Show an item from a particular category'''
    try:
        category = session.query(Category).filter_by(
            name=category_name).first()
        if category is not None:
            item = session.query(Item).filter_by(category_id=category.id,
                                                 name=item_name).first()
            items = session.query(Item).filter_by(category_id=category.id
                                                  ).order_by(Item.category_id
                                                             ).all()
            try:
                suser_id = login_session['user_id']
            except:
                suser_id = None
            if 'username' not in login_session or item.user_id != suser_id:
                return render_template('public_item.html',
                                       category=category, item=item,
                                       items=items)
            else:
                return render_template('item.html',
                                       category=category,
                                       item=item, items=items)
        else:
            return "No Item Info to display"
    except:
        print("show_item: Exception communicating with the database.")


@app.route('/catalog/<category_name>/<item_name>/edit/',
           methods=['GET', 'POST'])
def edit_item(category_name, item_name):
    ''' Edit an item from a particular category'''
    if 'username' not in login_session:
        return redirect('/login')
    try:
        categories = session.query(Category).all()
        category = session.query(Category).filter_by(name=category_name
                                                     ).first()
        if category is not None:
            item = session.query(Item).filter_by(category_id=category.id,
                                                 name=item_name).first()

        # Check to see if the user is authorized to edit the item.
        try:
            suser_id = login_session['user_id']
        except:
            suser_id = None
        if item.user_id != suser_id or suser_id is None:
            flash("Unauthorized to edit the item")
            return redirect(url_for('show_item',
                                    category_name=category_name,
                                    item_name=item_name))

        if request.method == 'GET':
            return render_template('edit_item.html',
                                   categories=categories, item=item)
        else:
            if request.form['submit'] == "Update":
                item.description = request.form['itemName']
                item.category_id = request.form['categoryId']
                updatedCategory = session.query(Category).filter_by(
                    id=item.category_id).one()
                category_name = updatedCategory.name
                session.add(item)
                session.commit()
                flash("Item has been updated sucessfully!")
            return redirect(url_for('show_category_items',
                                    category_name=category_name))
    except:
        print("edit_item: Exception communicating with the database.")


@app.route('/catalog/<category_name>/<item_name>/delete/',
           methods=['GET', 'POST'])
def delete_item(category_name, item_name):
    ''' Delete item from a particular category'''
    if 'username' not in login_session:
        return redirect('/login')
    try:
        category = session.query(Category).filter_by(name=category_name
                                                     ).first()
        if category is not None:
            item = session.query(Item).filter_by(category_id=category.id,
                                                 name=item_name).first()

        # Check to see if the user is authorized to edit the item.
        try:
            suser_id = login_session['user_id']
        except:
            suser_id = None
        if item.user_id != suser_id or suser_id is None:
            flash("Unauthorized to delete the item")
            return redirect(url_for('show_item',
                                    category_name=category_name,
                                    item_name=item_name))
        if request.method == 'GET':
            return render_template('delete_item.html',
                                   category=category, item=item)
        else:
            if request.form['submit'] == 'Delete':
                session.delete(item)
                session.commit()
                flash("Item has been deleted sucessfully!")
            return redirect(url_for('show_category_items',
                                    category_name=category_name))
    except:
        print("delete_item: Exception communicating with the database.")


@app.route('/catalog/<category_name>/items/new/', methods=['GET', 'POST'])
def add_item(category_name):
    ''' Add a new item to a particular category'''
    if 'username' not in login_session:
        return redirect('/login')
    try:
        if request.method == 'GET':
            categories = session.query(Category).all()
            return render_template('add_item.html', categories=categories)
        else:
            if request.form['submit'] == 'Add':
                category_id = request.form['categoryName']
                # check here for the selected category
                item_name = request.form['itemName']
                item_description = request.form['itemDescription']
                user_id = login_session['user_id']
                category = session.query(Category).filter_by(id=category_id
                                                             ).one()
                category_name = category.name
                item = Item(name=item_name, description=item_description,
                            category_id=category_id, user_id=user_id)
                session.add(item)
                session.commit()
                flash("Item has been added successfully!")
            return redirect(url_for('show_category_items',
                                    category_name=category_name))
    except:
        print("add_item: Exception communicating with the database.")


@app.route('/catalog/new/', methods=['GET', 'POST'])
def add_category():
    '''Add a new category'''
    if 'username' not in login_session:
        return redirect('/login')
    try:
        if request.method == 'GET':
            return render_template('add_category.html')
        else:
            if request.form['submit'] == "Add":
                category_name = request.form['categoryName']
                user_id = login_session['user_id']
                category = Category(name=category_name, user_id=user_id)
                session.add(category)
                session.commit()
                flash("Category has been created successfully!")
            return redirect(url_for('show_categories'))
    except:
        print("add_category: Exception communicating with the database.")


# Currently edit_category feature is not implemented fully
# There is a scope for future enhancement
# @app.route('/catalog/<category_name>/edit/')
def edit_category(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    category = {'name': 'Electronics1', 'id': '1'}
    # Check to see if the user is authorized to edit the item.
    try:
        suser_id = login_session['user_id']
    except:
        suser_id = None
    if category.user_id != suser_id or suser_id is None:
        flash("Unauthorized to edit the category")
        return redirect(url_for('show_categories'))
    return render_template('edit_category.html', category=category)


# Delete category is also implemented fully because of the complexity i.e.
# all the items belonging to category need to be
# category, so leaving it for future enhancement
# @app.route('/catalog/<category_name>/delete/')
def delete_category(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    category = {'name': 'Electronics', 'id': '1'}
    # Check to see if the user is authorized to edit the item.
    try:
        suser_id = login_session['user_id']
    except:
        suser_id = None
    if category.user_id != suser_id or suser_id is None:
        flash("Unauthorized to delete the category")
        return redirect(url_for('show_categories'))

    return render_template('delete_category.html', category=category)


# Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login')
def showLogin():
    '''Redirect to the google login page'''
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    '''Login using google OAuth'''
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret_catalog.json',
                                             scope='')
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
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
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

    # See if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    return output


@app.route('/gdisconnect')
def gdisconnect():
    '''Logout and clear the session'''
    access_token = login_session.get('access_token')
    if access_token is None:
        print ('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print ('In gdisconnect access token is %s', access_token)
    print ('User name is: ')
    print (login_session['username'])
    gurl = 'https://accounts.google.com/o/oauth2/revoke?token=%s'
    url = gurl % login_session['access_token']
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
        return redirect(url_for('show_categories'))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Implement Local authorization system.
def createUser(login_session):
    ''' Create new user with information collected from the google
        oauth api call and return the user_id '''
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    ''' Return user information collected from the google OAuth api'''
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    ''' Return user id if email is found in the user table'''
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# API Endpoints with JSON
@app.route("/catalog/JSON/")
def show_categoriesJSON():
    ''' Return all the categories from the database. '''
    categories = session.query(Category).all()
    return jsonify(Categories=[category.serialize for category in categories])


@app.route('/catalog/<category_name>/items/JSON/')
def show_category_itemsJSON(category_name):
    ''' Return all the items from a particular category. '''
    category = session.query(Category).filter_by(name=category_name).first()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return jsonify(Items=[item.serialize for item in items])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='localhost', port=5002)
