# Project - Catalog

##### Introduction
This is a web application which provides us the ability to add new categories and 
to add new items within those categories. Major features include
*   Add new categories
*   Add items within those categories
*   Edit or delete items from a category
*   Move items from one category to another
*   Lists the 5 latest items on the home page
*   Google OAuth is used for signin and signout, in other words you can signin using your gmail account.
*   Authorization is implemented i.e. URL's are protected from unauthorized access.
*   Only authorized users will be able to modify or delete the items.

##### Technologies used
* Python3
* Flask - Web development framework for python
* Sqlalchemy for ORM
* Sqlite for database
* Google OAuth2 API

##### Install
* Can be run on any computer provided we have all the softwares and tools installed.
* Python version 3 is required to run the application 
* Sqlite needs to be installed for database
    * pip3 install sqlite3
* Other miscellaneous modules need to be installed like sqlalchemy, flask, etc
* No special tools or IDE required, an editor like notepad, notepad++, etc to edit the code files.
* Additionally, google account is required to setup the project for Google OAuth API.
    *   Read the instructions [here]("https://developers.google.com/identity/protocols/OAuth2") for more information on OAuth
*  Brief steps include creating a google account, setting up a project, noting down the client ID
        and client secret, downloading the client secret json file, etc.

##### Instructions to run
* Unzip the python catalog project.
* The directory structure should be as follows
* * `catalogViews.py, catalog.db, client_secret_catalog.json, models.py` in the root directory
* * all .css files should go in the static folder inside the root directory
* * all .html files should go in the templates folder inside the root directory
* See the directory structure below:
    ```
    project
    │   README.md
    │   catalogViews.py    
    │   catalog.db
    │   client_secret_catalog.json
    │   models.py
    └─── static/css
    │   │   style.css
    │   │   bootstrap.css
    │   
    └───templates
        │   add_category.html
        │   add_item.html
        │   catalog.html
        │   category.html
        │   delete_category.html
        │   delete_item.html
        │   edit_category.html
        │   edit_item.html
        │   item.html
        │   login.html
        │   public_catalog.html
        │   public_category.html
        │   public_item.html
    ``` 
* Run the `catalogViews.py` program from within the IDLE or python shell and the server
 will run on localhost and port: 5002
    *   Command to run the application `python catalogViews.py`
* Goto [localhost@5002]("http://localhost:5002") from within the browser in order to access the catalog project's home page.

##### Scope for improvement
* There is a partial implementation for 'Deleting and Modifying a category' but there is a scope to make 
  it functional.
* Would love to provide a picture upload option while adding the categories and/or items.