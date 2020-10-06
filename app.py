from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


# LOGIN CHECK DECORATOR
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedIn' in session:
            return f(*args, **kwargs)
        else:
            flash('You must log in to view this page', 'warning')
            return redirect(url_for('login'))

    return decorated_function


# ADMIN CHECK
def adminCheck():
    if session['username'] == 'admin':
        return True
    else:
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


app = Flask(__name__)
app.secret_key = 'ismailgunay'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'ismailgunay'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)


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

    cursor = mysql.connection.cursor()

    if adminCheck():
        query = 'SELECT * FROM articles'
        result = cursor.execute(query)

    else:
        query = 'SELECT * FROM articles WHERE author = %s'
        result = cursor.execute(query, (session['username'],))

    if result > 0:
        articles = cursor.fetchall()
        return render_template('dashboard.html', articles=articles)

    else:
        return render_template('dashboard.html')


# ARTICLES
@app.route('/articles')
def articles():
    cursor = mysql.connection.cursor()

    query = 'SELECt * FROM articles'

    result = cursor.execute(query)

    if result > 0:
        articles = cursor.fetchall()
        return render_template('articles.html', articles=articles)

    else:
        return render_template('articles.html')


# USER ARTICLES
@app.route('/userArticles/<string:author>')
def userArticles(author):
    cursor = mysql.connection.cursor()

    query = 'SELECT * FROM articles WHERE author = %s'

    result = cursor.execute(query, (author,))

    if result > 0:
        articles = cursor.fetchall()
        return render_template('userArticles.html', articles=articles, author=author)

    else:
        return render_template('userArticles.html')


# ARTICLE
@app.route('/article/<string:id>')
def detail(id):
    cursor = mysql.connection.cursor()

    query = 'SELECT * FROM articles WHERE id = %s'

    result = cursor.execute(query, (id,))

    if result > 0:
        article = cursor.fetchone()
        return render_template('article.html', article=article)
    else:
        return render_template('article.html')


# ADD ARTICLE
@app.route('/addArticle', methods=['GET', 'POST'])
@login_required
def addArticle():

    form = ArticleForm(request.form)

    if request.method == 'POST' and form.validate():

        title = form.title.data
        content = form.content.data

        cursor = mysql.connection.cursor()

        query = 'INSERT INTO articles(title, author, content) VALUES(%s, %s, %s)'

        cursor.execute(query, (title, session['username'], content))
        mysql.connection.commit()
        cursor.close()

        flash('Article has been added successfully', 'success')

        return redirect(url_for('dashboard'))

    else:
        return render_template('addArticle.html', form=form)


# EDIT ARTICLE
@app.route('/editArticle/<string:id>', methods=['GET', 'POST'])
@login_required
def editArticle(id):

    if request.method == 'GET':
        cursor = mysql.connection.cursor()

        if adminCheck():
            query = 'SELECT * FROM articles WHERE id = %s'
            result = cursor.execute(query, (id,))

        else:
            query = 'SELECT * FROM articles WHERE id = %s and author = %s'
            result = cursor.execute(query, (id, session['username']))

        if result > 0:
            article = cursor.fetchone()
            form = ArticleForm()

            form.title.data = article['title']
            form.content.data = article['content']
            return render_template('editArticle.html', form=form)

        else:
            flash(
                'There is no such article or you may have not the permission to edit', 'warning')
            return redirect(url_for('dashboard'))

    else:

        form = ArticleForm(request.form)

        titleUpdated = form.title.data
        contentUpdated = form.content.data

        query = 'UPDATE articles SET title = %s, content = %s where id = %s'

        cursor = mysql.connection.cursor()

        cursor.execute(query, (titleUpdated, contentUpdated, id))
        mysql.connection.commit()

        flash('Article has been updated successfully', 'success')
        return redirect(url_for('dashboard'))


# DELETE ARTICLE
@app.route('/deleteArticle/<string:id>')
@login_required
def deleteArticle(id):
    cursor = mysql.connection.cursor()

    if adminCheck():
        query = 'SELECT * FROM articles WHERE id = %s'
        result = cursor.execute(query, (id,))

    else:
        query = 'SELECT * FROM articles WHERE author = %s and id = %s'
        result = cursor.execute(query, (session['username'], id))

    if result > 0:
        query = 'DELETE FROM articles WHERE id = %s'
        cursor.execute(query, (id,))
        mysql.connection.commit()

        flash('Article has been deleted successfully', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('There is no such article or you may have not the permission to delete', 'warning')
        return redirect(url_for('dashboard'))


# SEARCH ARTICLE
@app.route('/searchArticle', methods=['GET', 'POST'])
def searchArticle():

    if request.method == 'GET':
        return redirect(url_for('index'))

    else:
        keyword = request.form.get('keyword')

        cursor = mysql.connection.cursor()
        query = 'SELECT * FROM articles WHERE title LIKE "%' + keyword + '%" '

        result = cursor.execute(query)

        if result > 0:
            articles = cursor.fetchall()
            return render_template('searchArticle.html', articles=articles)

        else:
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

        cursor = mysql.connection.cursor()

        query = 'INSERT INTO users(name, username, email, password) VALUES(%s, %s, %s, %s)'

        cursor.execute(query, (name, username, email, password))
        mysql.connection.commit()
        cursor.close()

        flash('Successfully registered', 'success')

        return redirect(url_for('login'))
    else:
        return render_template('register.html', form=form)


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm(request.form)

    if request.method == 'POST':
        username = form.username.data
        passwordEntered = form.password.data

        cursor = mysql.connection.cursor()

        query = 'SELECT * FROM users WHERE username = %s'
        result = cursor.execute(query, (username,))

        if result > 0:
            data = cursor.fetchone()
            realPassword = data['password']

            if sha256_crypt.verify(passwordEntered, realPassword):
                flash('Successfully logged in', 'success')

                session['loggedIn'] = True
                session['username'] = username

                return redirect(url_for('index'))
            else:
                flash('Wrong password!', 'danger')
                return redirect(url_for('login'))

        else:
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
