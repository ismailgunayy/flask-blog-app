from functools import wraps
import sqlite3
from flask import Flask, render_template, flash, redirect, url_for, session, request
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt

dbConnection = sqlite3.connect("blog.db", check_same_thread=False)
dbConnection.row_factory = sqlite3.Row
dbCursor = dbConnection.cursor()

dbArticlesQuery = """CREATE TABLE IF NOT EXISTS articles(
                    articleID INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    author TEXT,
                    content TEXT,
                    created_date DATETIME DEFAULT CURRENT_TIMESTAMP
                    )"""

dbUsersQuery = """CREATE TABLE IF NOT EXISTS users(
                    userID INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    username TEXT,
                    email TEXT,
                    password TEXT
                )"""

dbCursor.execute(dbArticlesQuery)
dbCursor.execute(dbUsersQuery)
dbConnection.commit()


# APP SETTINGS
app = Flask(__name__)
app.secret_key = "flask-blog-app"
app.config["SESSION_TYPE"] = "filesystem"
app.static_folder = "static"


# LOGIN CHECK
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "loggedIn" in session:
            return f(*args, **kwargs)

        flash("You must log in to view this page", "warning")
        return redirect(url_for("login"))

    return decorated_function


# ADMIN CHECK
def adminCheck():
    if session["username"] == "admin":
        return True
    return False


# REGISTER FORM
class RegisterForm(Form):
    name = StringField("Full Name", validators=[validators.input_required()])
    username = StringField(
        "Username",
        validators=[validators.input_required(), validators.Length(min=5, max=30)],
    )
    email = StringField(
        "Email", validators=[validators.Email(message="Please type a valid email")]
    )
    password = PasswordField(
        "Password",
        validators=[
            validators.input_required(),
            validators.Length(min=7),
            validators.EqualTo(fieldname="confirm", message="Password don't match"),
        ],
    )
    confirm = PasswordField("Confirm Password")


# LOGIN FORM
class LoginForm(Form):
    username = StringField("Username")
    password = PasswordField("Password")


# ARTICLE FORM
class ArticleForm(Form):
    title = StringField("Article Title")
    content = TextAreaField("Article Content", validators=[validators.Length(min=23)])


# INDEX
@app.route("/")
def index():
    return render_template("index.html")


# INDEX 2
@app.route("/index")
def index2():
    return redirect(url_for("index"))


# ABOUT
@app.route("/about")
def about():
    return render_template("about.html")


# DASHBOARD
@app.route("/dashboard")
@login_required
def dashboard():

    if adminCheck():
        query = "SELECT * FROM articles"
        dbCursor.execute(query)
        result = dbCursor.fetchall()

    else:
        query = "SELECT * FROM articles WHERE author = ?"
        dbCursor.execute(query, (session["username"],))
        result = dbCursor.fetchall()

    if len(result) > 0:
        articles = result
        return render_template("dashboard.html", articles=articles)

    return render_template("dashboard.html")


# ARTICLES
@app.route("/articles")
def articles():

    query = "SELECt * FROM articles"

    dbCursor.execute(query)
    result = dbCursor.fetchall()

    if len(result) > 0:
        articles = result
        return render_template("articles.html", articles=articles)

    return render_template("articles.html")


# USER ARTICLES
@app.route("/userArticles/<string:author>")
def userArticles(author):

    query = "SELECT * FROM articles WHERE author = ?"

    dbCursor.execute(query, (author,))
    result = dbCursor.fetchall()

    if len(result) > 0:
        articles = result
        return render_template("userArticles.html", articles=articles, author=author)

    return render_template("userArticles.html")


# ARTICLE
@app.route("/article/<string:articleID>")
def detail(articleID):

    query = "SELECT * FROM articles WHERE articleID = ?"

    dbCursor.execute(query, (articleID,))
    result = dbCursor.fetchall()

    if len(result) > 0:
        article = result[0]
        return render_template("article.html", article=article)

    return render_template("article.html")


# ADD ARTICLE
@app.route("/addArticle", methods=["GET", "POST"])
@login_required
def addArticle():

    form = ArticleForm(request.form)

    if request.method == "POST" and form.validate():

        title = form.title.data
        content = form.content.data

        query = "INSERT INTO articles(title, author, content) VALUES(?, ?, ?)"

        dbCursor.execute(query, (title, session["username"], content))
        dbConnection.commit()

        flash("Article has been added successfully", "success")

        return redirect(url_for("dashboard"))

    return render_template("addArticle.html", form=form)


# EDIT ARTICLE
@app.route("/editArticle/<string:articleID>", methods=["GET", "POST"])
@login_required
def editArticle(articleID):

    if request.method == "GET":

        if adminCheck():
            query = "SELECT * FROM articles WHERE articleID = ?"
            dbCursor.execute(query, (articleID,))
            result = dbCursor.fetchall()

        else:
            query = "SELECT * FROM articles WHERE articleID = ? and author = ?"
            dbCursor.execute(query, (articleID, session["username"]))
            result = dbCursor.fetchall()

        if len(result) > 0:
            article = result[0]
            form = ArticleForm()

            form.title.data = article["title"]
            form.content.data = article["content"]
            return render_template("editArticle.html", form=form)

        flash(
            "There is no such article or you may have not the permission to edit",
            "warning",
        )
        return redirect(url_for("dashboard"))

    else:

        form = ArticleForm(request.form)

        titleUpdated = form.title.data
        contentUpdated = form.content.data

        query = "UPDATE articles SET title = ?, content = ? where articleID = ?"

        dbCursor.execute(query, (titleUpdated, contentUpdated, articleID))
        dbConnection.commit()

        flash("Article has been updated successfully", "success")
        return redirect(url_for("dashboard"))


# DELETE ARTICLE
@app.route("/deleteArticle/<string:articleID>")
@login_required
def deleteArticle(articleID):

    if adminCheck():
        query = "SELECT * FROM articles WHERE articleID = ?"
        dbCursor.execute(query, (articleID,))
        result = dbCursor.fetchall()

    else:
        query = "SELECT * FROM articles WHERE author = ? and articleID = ?"
        dbCursor.execute(query, (session["username"], articleID))
        result = dbCursor.fetchall()

    if len(result) > 0:
        query = "DELETE FROM articles WHERE articleID = ?"
        dbCursor.execute(query, (articleID,))
        dbConnection.commit()

        flash("Article has been deleted successfully", "success")
        return redirect(url_for("dashboard"))

    flash(
        "There is no such article or you may have not the permission to delete",
        "warning",
    )
    return redirect(url_for("dashboard"))


# SEARCH ARTICLE
@app.route("/searchArticle", methods=["GET", "POST"])
def searchArticle():

    if request.method == "GET":
        return redirect(url_for("index"))

    else:
        keyword = request.form.get("keyword")

        query = 'SELECT * FROM articles WHERE title LIKE "%' + keyword + '%" '
        query2 = 'SELECT * FROM articles WHERE content LIKE "%' + keyword + '%"'

        dbCursor.execute(query)
        result = dbCursor.fetchall()
        dbCursor.execute(query2)
        result = list(set(result + dbCursor.fetchall()))

        if len(result) > 0:
            articles = result
            return render_template("searchArticle.html", articles=articles)

        flash("There is no article includes {}".format(keyword), "warning")
        return redirect(url_for("articles"))


# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():

    form = RegisterForm(request.form)

    if request.method == "POST" and form.validate():

        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)

        checkQuery = "SELECT * FROM users WHERE username = ? or email = ?"

        dbCursor.execute(checkQuery, (username, email))
        result = list(set(dbCursor.fetchall()))

        for article in tuple(result):
            if article[2] == "username":
                flash("There is already a user who use this username", "warning")
                return redirect(url_for("register"))

            elif article[3] == email:
                flash("There is already a user who use this email", "warning")
                return redirect(url_for("register"))

        query = "INSERT INTO users(name, username, email, password) VALUES(?, ?, ?, ?)"

        dbCursor.execute(query, (name, username, email, password))
        dbConnection.commit()

        flash("Successfully registered", "success")

        return redirect(url_for("login"))

    return render_template("register.html", form=form)


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():

    form = LoginForm(request.form)

    if request.method == "POST":
        username = form.username.data
        passwordEntered = form.password.data

        query = "SELECT * FROM users WHERE username = ?"
        dbCursor.execute(query, (username,))
        result = dbCursor.fetchall()

        if len(result) > 0:
            data = result[0]
            realPassword = data["password"]

            if sha256_crypt.verify(passwordEntered, realPassword):
                flash("Successfully logged in", "success")

                session["loggedIn"] = True
                session["username"] = username

                return redirect(url_for("index"))

            flash("Wrong password!", "danger")
            return redirect(url_for("login"))

        flash("There is no user named {}".format(username), "danger")
        return redirect(url_for("login"))

    else:
        return render_template("login.html", form=form)


# LOGOUT
@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Successfully logged out", "success")
    return redirect(url_for("index"))


# ERROR
@app.errorhandler(404)
def errorHandler404(e):
    return render_template("404.html"), 404


app.register_error_handler(404, errorHandler404)
if __name__ == "__main__":
    app.run(host="localhost", port=5000, debug=True)
