from datetime import timedelta
from flask import *
import psycopg2
from configparser import ConfigParser
from flask_bcrypt import Bcrypt


config = ConfigParser()
config.read('config.ini')

db_host = config.get('database', 'host')
db_port = config.get('database', 'port')
db_name = config.get('database', 'database')
db_user = config.get('database', 'user')
db_password = config.get('database', 'password')

conn = psycopg2.connect(
    host=db_host,
    port=db_port,
    database=db_name,
    user=db_user,
    password=db_password
)

cur = conn.cursor()

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'HI_MOM!'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)


@app.route('/')
def hello_world():  # put application's code here
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        flash('You are already logged in', 'danger')
        return redirect(url_for('user', username=session['user']))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == '' or password == '':
            flash('Please fill out all fields', 'danger')
            return redirect(url_for('login'))

        print(username)

        cur.execute("SELECT * FROM users WHERE username = %s ", (username,))
        passwords = cur.fetchone()
        db_password1 = passwords[1]
        print("alo")
        print(bytes(db_password1).decode('utf-8'))

        if not bcrypt.check_password_hash(bytes(db_password1), password):
            flash('Invalid username', 'danger')
            return redirect(url_for('login'))

        else:
            print(username + " logged in")
            # Set session variable
            session['user'] = username
            flash('You are now logged in', 'success')
            conn.close()
            return redirect(url_for('user', username=session['user']))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']




        if username == '' or password == '':
            flash('Please fill out all fields', 'danger')
            return redirect(url_for('register'))

        if username.isnumeric():
            flash('Username cannot be a number', 'danger')
            return redirect(url_for('register'))

        if password != password2:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        print(username)

        password = bcrypt.generate_password_hash(password, 10)

        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        if user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        conn.commit()

        flash('You are now registered and can login', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/user-<username>')
def user():
    if 'user' in session:
        return render_template('user.html', username=session['user'])
    else:
        flash('You are not logged in, please login', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run()
