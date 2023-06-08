from datetime import timedelta
from flask import *
from flask_bcrypt import Bcrypt
import scraper
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import URL, DataRequired
from datetime import timedelta
from flask import *
import psycopg2
from configparser import ConfigParser
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFProtect

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
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
csrf = CSRFProtect(app)


@app.route('/')
def index():
    return render_template('index.html')


# Route to handle the form submission
class ScrapeForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired(), URL()])
    submit = SubmitField('Scrape')


@app.route('/scrapeUrl', methods=['GET', 'POST'])
def scrape_url():
    form = ScrapeForm()

    if form.validate_on_submit():
        url = form.url.data

        if not scraper.is_valid_url(url):
            return render_template('scrape_url.html', form=form, error='Invalid URL')

        # scrape the url
        scraped_text = scraper.get_text(url)
        session['scraped_urls'] = url

        if scraped_text and 'user' in session:
            user = session['user']
            print("Adding scraped url to database...")
            try:
                #get the user id
                cur.execute("SELECT id FROM users WHERE username = %s", (user,))
                user_id = cur.fetchone()[0]
                cur.execute("INSERT INTO scraped_urls (url, user_id) VALUES (%s, %s)", (url, user_id,))
                conn.commit()
                print("Scraped url added to database")
            except Exception as e:
                flash('Error: ' + str(e), 'danger')
                print("Error: " + str(e))
                conn.rollback()
            return render_template('scrape_url.html', form=form, scraped_text=scraped_text)

        return render_template('scrape_url.html', form=form, scraped_text=scraped_text)

    return render_template('scrape_url.html', form=form)


@app.route('/summarize', methods=['GET', 'POST'])
def summarize_text():
    url_to_scrape = session.get('scraped_urls')
    scraped_text = scraper.get_text(url_to_scrape)

    if scraped_text:
        summarized_text = scraper.summarize_text(scraped_text)
    else:
        summarized_text = 'No scraped text found.'

    session['summarized_text'] = summarized_text

    return render_template('summary.html', summarized_text=summarized_text)


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
        try:
            cur.execute("SELECT * FROM users WHERE username = %s ", (username,))
            passwords = cur.fetchone()
        except Exception as e:
            flash('Error: ' + str(e), 'danger')
            conn.rollback()
            return redirect(url_for('login'))
        if passwords is None:
            flash('Invalid username', 'danger')
            return render_template('login.html')
        db_password1 = passwords[1]

        if not bcrypt.check_password_hash(bytes(db_password1), password):
            flash('Invalid username', 'danger')
            return redirect(url_for('login'))

        else:
            print(username + " logged in")
            # Set session variable
            session['user'] = username
            flash('You are now logged in', 'success')

            return redirect(url_for('user', username=session['user']))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        flash('You are already logged in', 'danger')
        return redirect(url_for('user', username=session['user']))
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
        try:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
        except Exception as e:
            flash('Error: ' + str(e), 'danger')
            conn.rollback()
            return redirect(url_for('register'))

        if user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
            conn.commit()
            session['user'] = username
            flash('You are now registered and can login', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Error registering: ' + str(e), 'danger')
            conn.rollback()
            return redirect(url_for('register'))


    return render_template('register.html')


@app.route('/<username>_dashboard')
def user(username):
    if 'user' in session:
        scraped_urls = get_scraped_urls(username)

        #make a list of the urls but make them cleaner
        cleaned_urls = [url[0].strip('()') for url in scraped_urls]
        urls = '<br>'.join(cleaned_urls)
        print(urls)
        #make a list of the urls but make them cleaner



        return render_template('dashboard.html', username=username, scraped_urls=cleaned_urls)
    else:
        flash('You are not logged in', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


def get_scraped_urls(username):



    query = """
        SELECT url
        FROM scraped_urls
        WHERE user_id = (
            SELECT id
            FROM users
            WHERE username = %s
        );
    """
    try:
        cur.execute(query, (username,))
        urls = cur.fetchall()
    except Exception as e:
        print(e)
        urls = []
        conn.rollback()

    return urls


if __name__ == '__main__':
    app.run(debug=True)
