from flask import Flask, render_template, request, session, url_for, redirect, g
import pymysql.cursors
import hashlib

app = Flask(__name__)

conn = pymysql.connect(host='localhost',
                       user='root',
                       password='',
                       db='pricosha',
                       charset='utf8mb4',
                       cursorclass=pymysql.cursors.DictCursor)

def hashPassword(password):
    """CONVERT PASSWORD AND SALT TO BITS
       ENCRYPT BIT PASSWORD WITH SHA256
       ':' + SALT ADDED TO SPLIT LATER
       WHEN CHECKING"""
    hashedPass = hashlib.sha256(password.encode()).hexdigest()
    return hashedPass


def checkPassword(userPassword, hashedPassword):
    #CHECK IF HASHED USERPASSWORD = HASHEDPASSWORD (NO SALT
    hashedUserPass = hashlib.sha256(userPassword.encode()).hexdigest()
    return hashedPassword == hashedUserPass


#CHECKS FOR SESSION BEFORE HANDLING REQUESTS
@app.before_request
def before_request():
    g.user = None
    if 'username' in session:
        g.user = session['username']


@app.route('/') #TODO: CHANGE NAME OF TEMPLATE AND ROUTE
def login():
    if g.user:
        return redirect(url_for('profile'))

    return render_template('login.html')


#AUTHENTICATES REGISTRATION
@app.route('/registerAuth', methods=['GET', 'POST'])
def registerAuth():
    if g.user:
        return redirect(url_for('profile'))
    #GET DATA FROM FORMS
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    username = request.form['username']
    password = hashPassword(request.form['password'])
    #MAKE CURSOR FOR QUERIES
    cursor = conn.cursor()
    query = 'SELECT username FROM Person WHERE username = %s'
    #EXECUTE QUERY
    cursor.execute(query, (username))
    #STORE QUERY RESULTS IN DATA VARIABLE
    data = cursor.fetchone()
    if (data):
        #USERNAME ALREADY EXISTS. DISPLAY ERROR
        registerError = 'This user is already registered'
        cursor.close()
        return render_template('login.html', loginError=None, registerError=registerError)
    else:
        #INSERT FORM DATA INTO PERSON TABLE
        insert = 'INSERT INTO Person (username, password, first_name, last_name) VALUES (%s, %s, %s, %s)'
        cursor.execute(insert, (username, password, first_name, last_name))
        conn.commit()
        cursor.close()
        session['username'] = username
        return redirect(url_for('profile')) #TODO: MAKE PROFILE TEMPLATE TO RENDER


@app.route('/loginAuth', methods=['GET', 'POST'])
def loginAuth():
    #GET DATA FROM FORMS
    username = request.form['username']
    password = request.form['password']
    #MAKE CURSOR FOR QUERIES
    cursor = conn.cursor()
    #EXECUTE QUERY
    query = 'SELECT username, password FROM Person WHERE username = %s'
    cursor.execute(query, username)
    #STORE QUERY RESULTS IN DATA VARIABLE AND CLOSE CURSOR
    data = cursor.fetchone()
    cursor.close()
    loginError = None
    if data and checkPassword(password, data['password']):
        #CREATE SESSION FOR USER
        session['username'] = username
        #REDIRECT USER TO PROFILE PAGE
        return redirect(url_for('profile')) #TODO: MAKE PROFILE.HTML LOOK GOOD
    else:
        #RENDER LOGIN PAGE WITH ERROR MESSAGE
        loginError = 'Invalid login or username'
        return render_template('login.html', loginError=loginError, registerError=None)


@app.route('/logout')
def logout():
    session.pop('username')
    return redirect('/')


@app.route('/profile')
def profile():
    if g.user is None:
        return redirect('/')
    return render_template('profile.html')


app.secret_key = 'some key that you will never guess'


if __name__ == "__main__":
    app.run('127.0.0.1', 5000, debug=True)
