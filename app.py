from functools import wraps
import sqlite3
from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt

dbConnection = sqlite3.connect('blog.db', check_same_thread=False)
dbConnection.row_factory = sqlite3.Row
dbCursor = dbConnection.cursor()

dbArticlesQuery = """CREATE TABLE IF NOT EXISTS articles(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    author TEXT,
                    content TEXT,
                    created_date DATETIME DEFAULT CURRENT_TIMESTAMP
                    )"""

dbUsersQuery = """CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    username TEXT,
                    email TEXT,
                    password TEXT
                )"""

dbCursor.execute(dbArticlesQuery)
dbCursor.execute(dbUsersQuery)
dbConnection.commit()

app = Flask(__name__)
app.secret_key = 'flaskBlogApp'
app.config['SESSION_TYPE'] = 'filesystem'

# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = ''
# app.config['MYSQL_DB'] = 'ismailgunay'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# mysql = MySQL(app)


# LOGIN CHECK DECORATOR
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedIn' in session:
            return f(*args, **kwargs)

        flash('You must log in to view this page', 'warning')
        return redirect(url_for('login'))

    return decorated_function


# ADMIN CHECK
def adminCheck():
    if session['username'] == 'admin':
        return True
    return False


# REGISTER FORM CLASS
class RegisterForm(Form):
    name = StringField("Full Name", validators=[validators.input_required()])
    username = StringField('Username', validators=[
                           validators.input_required(), validators.Length(min=5, max=30)])
    email = StringField('Email', validators=[
                        validators.Email(message='Please type a valid email')])
    password = PasswordField('Password', validators=[
        validators.input_required(), validators.Length(min=7), validators.EqualTo(
            fieldname='confirm', message='Password don\'t match')
    ])
    confirm = PasswordField('Confirm Password')


# LOGIN FORM CLASS
class LoginForm(Form):
    username = StringField('Username')
    password = PasswordField('Password')


# INDEX
@app.route('/')
def index():
    return render_template('index.html')


# ABOUT
@app.route('/about')
def about():
    return render_template('about.html')


# DASHBOARD
@app.route('/dashboard')
@login_required
def dashboard():

    if adminCheck():
        query = 'SELECT * FROM articles'
        dbCursor.execute(query)
        result = dbCursor.fetchall()

    else:
        query = 'SELECT * FROM articles WHERE author = ?'
        dbCursor.execute(query, (session['username'],))
        result = dbCursor.fetchall()

    if len(result) > 0:
        articles = result
        return render_template('dashboard.html', articles=articles)

    return render_template('dashboard.html')


# ARTICLES
@app.route('/articles')
def articles():

    query = 'SELECt * FROM articles'

    dbCursor.execute(query)
    result = dbCursor.fetchall()

    if len(result) > 0:
        articles = result
        return render_template('articles.html', articles=articles)

    return render_template('articles.html')


# USER ARTICLES
@app.route('/userArticles/<string:author>')
def userArticles(author):

    query = 'SELECT * FROM articles WHERE author = ?'

    dbCursor.execute(query, (author,))
    result = dbCursor.fetchall()

    if len(result) > 0:
        articles = result
        return render_template('userArticles.html', articles=articles, author=author)

    return render_template('userArticles.html')


# ARTICLE
@app.route('/article/<string:id>')
def detail(id):

    query = 'SELECT * FROM articles WHERE id = ?'

    dbCursor.execute(query, (id,))
    result = dbCursor.fetchall()

    if len(result) > 0:
        article = result[0]
        return render_template('article.html', article=article)

    return render_template('article.html')


# ADD ARTICLE
@app.route('/addArticle', methods=['GET', 'POST'])
@login_required
def addArticle():

    form = ArticleForm(request.form)

    if request.method == 'POST' and form.validate():

        title = form.title.data
        content = form.content.data

        query = 'INSERT INTO articles(title, author, content) VALUES(?, ?, ?)'

        dbCursor.execute(query, (title, session['username'], content))
        dbConnection.commit()

        flash('Article has been added successfully', 'success')

        return redirect(url_for('dashboard'))


    return render_template('addArticle.html', form=form)


# EDIT ARTICLE
@app.route('/editArticle/<string:id>', methods=['GET', 'POST'])
@login_required
def editArticle(id):

    if request.method == 'GET':

        if adminCheck():
            query = 'SELECT * FROM articles WHERE id = ?'
            dbCursor.execute(query, (id,))
            result = dbCursor.fetchall()

        else:
            query = 'SELECT * FROM articles WHERE id = ? and author = ?'
            dbCursor.execute(query, (id, session['username']))
            result = dbCursor.fetchall()

        if len(result) > 0:
            article = result[0]
            form = ArticleForm()

            form.title.data = article['title']
            form.content.data = article['content']
            return render_template('editArticle.html', form=form)


        flash(
            'There is no such article or you may have not the permission to edit', 'warning')
        return redirect(url_for('dashboard'))

    else:

        form = ArticleForm(request.form)

        titleUpdated = form.title.data
        contentUpdated = form.content.data

        query = 'UPDATE articles SET title = ?, content = ? where id = ?'

        dbCursor.execute(query, (titleUpdated, contentUpdated, id))
        dbConnection.commit()

        flash('Article has been updated successfully', 'success')
        return redirect(url_for('dashboard'))


# DELETE ARTICLE
@app.route('/deleteArticle/<string:id>')
@login_required
def deleteArticle(id):

    if adminCheck():
        query = 'SELECT * FROM articles WHERE id = ?'
        dbCursor.execute(query, (id,))
        result = dbCursor.fetchall()

    else:
        query = 'SELECT * FROM articles WHERE author = ? and id = ?'
        dbCursor.execute(query, (session['username'], id))
        result = dbCursor.fetchall()

    if len(result) > 0:
        query = 'DELETE FROM articles WHERE id = ?'
        dbCursor.execute(query, (id,))
        dbConnection.commit()

        flash('Article has been deleted successfully', 'success')
        return redirect(url_for('dashboard'))

    flash('There is no such article or you may have not the permission to delete', 'warning')
    return redirect(url_for('dashboard'))


# SEARCH ARTICLE
@app.route('/searchArticle', methods=['GET', 'POST'])
def searchArticle():

    if request.method == 'GET':
        return redirect(url_for('index'))

    else:
        keyword = request.form.get('keyword')

        query = 'SELECT * FROM articles WHERE title LIKE "%' + keyword + '%" '

        dbCursor.execute(query)
        result = dbCursor.fetchall()

        if len(result) > 0:
            articles = dbCursor.fetchall()
            return render_template('searchArticle.html', articles=articles)

        flash('There is no article includes {}'.format(keyword), 'warning')
        return redirect(url_for('articles'))


# ARTICLE FORM
class ArticleForm(Form):
    title = StringField('Article Title')
    content = TextAreaField('Article Content', validators=[
                            validators.Length(min=23)])


# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():

    form = RegisterForm(request.form)

    if request.method == 'POST' and form.validate():

        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)

        query = 'INSERT INTO users(name, username, email, password) VALUES(?, ?, ?, ?)'

        dbCursor.execute(query, (name, username, email, password))
        dbConnection.commit()

        flash('Successfully registered', 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm(request.form)

    if request.method == 'POST':
        username = form.username.data
        passwordEntered = form.password.data

        query = 'SELECT * FROM users WHERE username = ?'
        dbCursor.execute(query, (username,))
        result = dbCursor.fetchall()

        if len(result) > 0:
            data = result[0]
            print(result)
            print(data)
            print(type(data))
            realPassword = data['password']

            if sha256_crypt.verify(passwordEntered, realPassword):
                flash('Successfully logged in', 'success')

                session['loggedIn'] = True
                session['username'] = username

                return redirect(url_for('index'))

            flash('Wrong password!', 'danger')
            return redirect(url_for('login'))

        flash('There is no user named {}'.format(
            username), 'danger')
        return redirect(url_for('login'))

    else:
        return render_template('login.html', form=form)


# LOGOUT
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Successfully logged out', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)



