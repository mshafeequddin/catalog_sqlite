#!/usr/bin/env python3
#
# Catalog Project
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy.engine import create_engine
from models import Base, User, Category, Item
from sqlalchemy.orm.session import sessionmaker
app = Flask(__name__)

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


@app.route('/catalog/<category_name>/<item_name>/delete/', methods = ['GET', 'POST'])
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
