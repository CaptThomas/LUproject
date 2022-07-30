#!/usr/bin/python3
import os
from functools import wraps
from flask import Flask, flash, jsonify, redirect, render_template, request, session, send_from_directory
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from sqlite3 import Error
import requests
import urllib.parse
import uuid
import re
from datetime import date
from html_sanitizer import Sanitizer

app = Flask(__name__)

sanitizer = Sanitizer()

app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
if __name__ == '__main__':
    app.run(host='0.0.0.0:80')

def create_connection(path):
    connection = None
    try:
        connection = sqlite3.connect(path)
        print("Connection to SQLite DB successful")
    except Error as e:
        print(f"The error '{e}' occurred")

    return connection
connection = create_connection("orso.db")
regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
def checkmail(email):

    # pass the regular expression
    # and the string in search() method
    if(re.search(regex,email)):
        return(1)

    else:
        return(0)
def execute_read_query(connection, query):
    cursor = connection.cursor()
    result = None
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Error as e:
        print(f"The error '{e}' occurred")
def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        print("Query executed successfully")
    except Error as e:
        print(f"The error '{e}' occurred")
def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function
@app.route('/blog/<path:path>', methods=["GET", "POST"])
@login_required
def send_blog(path):
    if request.method == "POST":
        if not request.form.get("comments"):
            return render_template(f"blog/{path}.html", popup="Enter a comment")
        elif request.form.get("comments") == "Enter up to 255 characters":
            return render_template(f"blog/{path}.html", popup="Enter a comment")
        elif len(request.form.get("comments")) > 255:
            return render_template(f"blog/{path}.html", popup="Please limit yourself to 255 characters")
        body = sanitizer.sanitize(request.form.get("comments"))
        testuuid = session["user_id"]
        select_query = f"SELECT username FROM users WHERE uuid = '{testuuid}';"
        rows = execute_read_query(connection, select_query)
        author = sanitizer.sanitize(rows[0][0])
        datepublished = (date.today()).strftime("%m/%d/%Y")
        select_query = f"SELECT id FROM feed WHERE uuid='{path}';"
        rows = execute_read_query(connection, select_query)
        query = f"INSERT INTO comments{rows[0][0]} (author, date, body) VALUES ('{author}', '{datepublished}', '{body}');"
        execute_query(connection, query)
        return redirect(f"/blog/{path}")
    else:
        select_query = f"SELECT id FROM feed WHERE uuid='{path}';"
        rows = execute_read_query(connection, select_query)
        select_query = f"SELECT * FROM comments{rows[0][0]} ORDER BY id;"
        comments = execute_read_query(connection, select_query)
        return render_template(f"blog/{path}.html", comments=comments)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Logs a user in"""

    # Forgets any user_id
    session.clear()

    # User reached route via POST; usually by subitting a form to login
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("login.html", popup="Ensure that you submitted a username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("login.html", popup="Password cannot be blank")

        # Query database for username
        username=request.form.get("username")
        check_query = (
            f"SELECT * FROM users WHERE username = '{username}';"
            )
        rows = execute_read_query(connection, check_query)
        # Ensure username exists and password is correct
        if not rows:
            return render_template("login.html", popup="Invalid username and/or password")
        elif not check_password_hash(rows[0][2], request.form.get("password")):
            return render_template("login.html", popup="Invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0][0]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
@app.route("/register", methods=["GET", "POST"])
def register():
    """Registers a user"""

    # Forgets any user_id
    session.clear()

    # User reached route via POST by registering
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("register.html", popup="Must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("register.html", popup="Must provide password")

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return render_template("register.html", popup="Must re-enter password")

        elif not request.form.get("email"):
            return render_template("register.html", popup="Enter a valid email")

        elif not request.form.get("bday"):
            return render_template("register.html", popup="Enter your birthday")

        elif not request.form.get("password") == request.form.get("confirmation"):
            return render_template("register.html", popup="Verify your passwords match")

        elif not checkmail(request.form.get("email")):
            return render_template("register.html", popup="Enter a valid email")

        # Query database for username
        username = request.form.get("username")
        select_query = f"SELECT * FROM users WHERE username = '{username}';"
        rows = execute_read_query(connection, select_query)
        # Ensure username doesn't exist
        if rows:
            return render_template("register.html", popup="Username already exists")

        bday = request.form.get("bday")

        password=request.form.get("password")
        hash = generate_password_hash(password)
        uniqueuuid = 0;
        while(uniqueuuid == 0):
            testuuid = str(uuid.uuid4())
            select_query = f"SELECT * FROM users WHERE uuid = '{testuuid}';"
            rows = execute_read_query(connection, select_query)
            if not rows:
                uniqueuuid = 1;
        email = request.form.get("email")

        insert_query = f"INSERT INTO users (uuid, username, hash, email, bday, admin) VALUES ('{testuuid}','{username}', '{hash}', '{email}', '{bday}', 0);"
        execute_query(connection, insert_query)
        # Redirects a user to the login page
        return redirect("/login")

    # User reached route via GET (as by clicking a link)
    else:
        today = date.today()
        maxdate = today.strftime("%Y-%m-%d")
        return render_template("register.html", maxdate=maxdate)
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Shows homepage"""
    if request.method == "GET":
        select_query = "SELECT * FROM feed ORDER BY id DESC;"
        row = execute_read_query(connection, select_query)
        return render_template("index.html", rows=len(row), feed=row)
@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    """Allows posting of blogs"""
    if request.method == "POST":
        if not request.form.get("title"):
            return render_template("post.html", popup="Create a title for your blog post")
        elif not request.form.get("content"):
            return render_template("post.html", popup="Add some content")
        elif request.form.get("content") == "Start typing...":
            return render_template("post.html", popup="Add some content")
        uuidpost = str(uuid.uuid4())
        datepublished = (date.today()).strftime("%m/%d/%Y")
        author = session["user_id"]
        select_query = f"SELECT username FROM users WHERE uuid = '{author}';"
        rows = execute_read_query(connection, select_query)
        filename = "templates/blog/" + uuidpost + ".html"
        f = open(f"{filename}", "a+")
        f.write("""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"><link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css" rel="stylesheet"><script src="https://code.jquery.com/jquery-3.3.1.min.js"></script><script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script><script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script><link href="/static/favicon.ico" rel="icon"><title>Orsolingo Community Blogs</title></head><body><div class="container-fluid"><nav class="navbar navbar-inverse"><div class="container-fluid"><div class="navbar-header"><a class="navbar-brand" href="/">Orsolingo</a></div><ul class="nav navbar-nav"> {% if session.user_id %} <li><a href="/">Home</a></li><li><a href="/post">Post Blog</a></li> {% endif %} </ul><ul class="nav navbar-nav navbar-right"> {% if session.user_id %} <li><a href="/logout"> Logout</a></li> {% endif %} </ul></div></nav><main class="container p-5">{% if popup %}<div class="alert alert-danger" role="alert">{{ popup }}</div>{% endif %}""")
        title = request.form.get("title")
        title = sanitizer.sanitize(title)
        f.write(f"""<p class="font-weight-bold" style="text-align:center;">{title}</p>""")
        author = sanitizer.sanitize(rows[0][0])
        datepublished = sanitizer.sanitize(datepublished)
        f.write(f"""<p class="font-weight-light" style="text-align:center;">Written by {author} on {datepublished}</p>""")
        content = sanitizer.sanitize(request.form.get("content"))
        f.write(f"""<p class="font-weight-normal" style="text-align:center;"><div class="w-auto p-3" word-wrap: break-word;>{content}</div></p>""")
        f.write("""<div class="w-100"><div><div class="w-100"></div><h2 style="text-align: center;">Comments</h2></div><form method="post"><div><textarea name="comments" id="comments" style="font-family:sans-serif;font-size:1.2em;">Enter up to 255 characters</textarea></div><input type="submit" value="Submit"></form><div>{% if comments %}{% for x in comments %}<div class="row"><div class="col"><strong>{{x[1]}}</strong></div><div class="col">{{x[2]}}</div><div class="w-100"></div><div class="col" word-wrap: break-word;>{{x[3]}}</div>{% endfor %}{% endif %}</div></div>""")
        f.write("""</main> </div> </body> </html>""")
        f.close
        if len(content) > 100:
            preview = ""
            for a in range(100):
                preview = preview + content[a]
            preview = preview + "..."
        else:
            preview = content
        query = f"INSERT INTO feed (uuid, title, author, pubdate, contprev) VALUES ('{uuidpost}', '{title}', '{author}', '{datepublished}', '{preview}');"
        execute_query(connection, query)
        select_query = f"SELECT id FROM feed WHERE uuid = '{uuidpost}';"
        rows = execute_read_query(connection, select_query)
        query = f"CREATE TABLE IF NOT EXISTS comments{rows[0][0]} (id INTEGER PRIMARY KEY, author varchar(255), date varchar(255), body text);"
        execute_query(connection, query)
        return redirect(f"/blog/{uuidpost}")
    else:
        return render_template("post.html")
@app.route("/logout")
def logout():
    """Logs a user out"""

    # Forget any user_id
    session.clear()

    # Redirects a user to the login form indirectly
    return redirect("/")
@app.route("/resetpass", methods=["GET", "POST"])
@login_required
def resetpass():
    if request.method == "POST":
         # Ensure username was submitted
        if not request.form.get("cpass"):
            return render_template("resetpass.html", popup="must provide current password")

        # Ensure password was submitted
        elif not request.form.get("npass1"):
            return render_template("resetpass.html", popup="must provide new password")

        # Ensure confirmation was submitted
        elif not request.form.get("npass2"):
            return render_template("resetpass.html", popup="must re-enter password")

        elif not request.form.get("npass1") == request.form.get("npass2"):
            return render_template("resetpass.html", popup="your passwords do not match")

        # Query database for all
        uuid = session["user_id"]
        select_query = f"""SELECT * FROM users WHERE uuid = '{uuid}';"""
        rows = execute_read_query(connection, select_query)

        # Ensure password is correct
        if not check_password_hash(rows[0][2], request.form.get("cpass")):
            return render_template("resetpass.html", popup="your password is incorrect")


        password=generate_password_hash(request.form.get("npass1"))
        query = f"""UPDATE users SET hash='{password}' WHERE uuid='{uuid}';"""
        execute_query(connection, query)

        return redirect("/")
    else:
        return render_template("resetpass.html")