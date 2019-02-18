from flask import *
from flask_bootstrap import Bootstrap
from urllib.request import urlopen
from flaskext.mysql import MySQL
from operator import itemgetter
from hashlib import sha256
import requests
import random
import re


########## notes ##########
#                         #
#      _____ ____         #
#                         #
###########################

def create_app():
    app = Flask(__name__)
    Bootstrap(app)
    return app



MAIL_GUN_API_KEY = "YOUR_API_KEY"
GOOGLE_RECAPTCH_V2_SECRET_KEY = "GOOGLE CAPTCHA KEY"

app = create_app()

DESCRIPTION = """Check the availability of Hytale Names, Find out if your desired Hytale Name has been claimed, and see who owns specific Hytale Account Names. Hytale Player lookup. """
KEYWORDS = """hytale, hytale names, hytale name availability, hytale name reservation, hytale beta, hytale release date, hytale game, hytale stats, hytale skins, hytale accounts, hytale lookup, hytale players, hytale download, hytale beta."""

mysql = MySQL()
app.config['DEBUG'] = True
app.config['CUSTOM_STATIC_PATH'] = 'templates'
app.config['MYSQL_DATABASE_USER'] = 'USER'
app.config['MYSQL_DATABASE_PASSWORD'] = 'PASSWD'
app.config['MYSQL_DATABASE_DB'] = 'DB'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)




conn = mysql.connect()
cursor = conn.cursor()


# Done.
def update(syntax):
    conn = mysql.connect()
    cursor = conn.cursor()
    cursor.execute(syntax)
    conn.commit()

# Done.
def execute(syntax, args):
    conn = mysql.connect()
    cursor = conn.cursor()
    cursor.execute(syntax, tuple(args) if type(args) != tuple else args)
    conn.commit()
    ret = []
    for cur in cursor:
        ret.append(cur) if len(cur) > 0 else 1 == 0

    return ret

# Done.
def search_name(arg):
    results = []
    results += (execute("SELECT * FROM names WHERE name=%s", [arg]))
    return list(set(results))

# Done.
def get_favorit_names():
    results = []
    results += (execute("SELECT * FROM names ORDER BY favorit DESC", ()))
    return sorted(list(set(results)), key=itemgetter(5))[::-1]

# Done.
def increment_search(search):
    execute("UPDATE names SET searches = searches + 1 WHERE name=%s", [search])

def increment_favorit(name_id):
    execute("UPDATE names SET favorit = favorit + 1 WHERE id=%s", [name_id])

def decrement_favorit(name_id):
    execute("UPDATE names SET favorit = favorit - 1 WHERE id=%s", [name_id])

def add_searched_name(search):
    execute("INSERT INTO names (name, time_created, searches) VALUES (%s, NOW(), 1)", ([str(search)]))


# Done.
def get_user(HASH, email):
    cursor = execute("SELECT * FROM users WHERE pass_hash=%s AND email=%s", [HASH, email])
    for cur in cursor:
        return list(cur)
    return False

def get_user_recover(hash):
    cursor = execute("SELECT * FROM users WHERE recover_hash=%s", [hash])
    for cur in cursor:
        return list(cur)
    return False

def register_user(id):
    execute("UPDATE users SET registred=%s", ("1"))

# Done.
def get_email(email):
    cursor = execute("SELECT * FROM users WHERE email=%s", [email])
    for cur in cursor:
        return cur[0]
    return False


# Will improve
def send_mail(email, subject, text):
    return requests.post(
        "https://api.mailgun.net/v3/hytalenames/messages",
        auth=("api", MAIL_GUN_API_KEY),
        data={"from": "Excited User <mailgun@hytalenames.org>",
              "to": [email, "no-reply@hytalenames.org"],
              "subject": subject,
              "text": text})



def hash_passwd(passwd):
    return sha256(bytes(passwd, "utf-8")).hexdigest()

def update_password(Hash, passwd):
    execute("UPDATE users SET passwd=%s WHERE recover_hash=%s", [passwd, Hash])

def save_recover_hash(Hash, email):
    execute("UPDATE users SET recover_hash=%s WHERE email=%s", [Hash, email])

def store_user(user_name, email, passwd):
    execute("INSERT INTO users (username, email, pass_hash, registred, recover_hash) VALUES (%s, %s, %s, %s, %s)", [user_name, email, hash_passwd(passwd), "", "0"])

def check_registred(id):
    cursor = execute("SELECT * FROM users WHERE id=%s AND registred=\"1\"", [str(id)])
    for _ in cursor:
        return True
    return False


def check_ip_like(ip, id):
    cursor = execute("SELECT * FROM likes WHERE user_ip=%s AND name_id=%s", [ip, int(id)])
    for _ in cursor:
        execute("DELETE FROM likes WHERE user_ip=%s AND name_id=%s", [ip, int(id)])
        decrement_favorit(id)
        return True
    execute("INSERT INTO likes (user_ip, name_id) VALUES (%s, %s)", [ip, int(id)])
    increment_favorit(id)
    return False



def checkRecaptcha(response, secretkey):
    url = 'https://www.google.com/recaptcha/api/siteverify?'
    url = url + 'secret=' +secretkey
    url = url + '&response=' +response
    try:
        jsonobj = json.loads(urlopen(url).read())
        if jsonobj['success']:
            return True
        else:
            return False
    except Exception as e:
        return False

# Progress
@app.route("/", methods=["GET"])
def route():
    results = get_favorit_names()
    return render_template("layout.html", best_names=results, page="main.html", title="Hytale Names", description=DESCRIPTION, keywords=KEYWORDS, logged_in=True if session.get("logged_in") else False)

# Progress
@app.route("/search")
def search():
    errmsg = []
    results = []
    if request.args.get("q"):
        search = request.args.get("q").strip()
        if (len(search) > 2):
            if (len(search) < 50):
                if (re.match(r"^[a-z0-9_-]{3,15}$", search) or search.isalnum()):
                    results = search_name(search)
                    if results:
                        if not session.get(search):
                            increment_search(search)
                            session[search] = True
                        else:
                            pass

                    else:
                        add_searched_name(search)

                else:
                    flash("Invalid name.")
            else:
                flash("too long.")
        else:
            flash("too short.")

    return render_template("layout.html", best_names=results, page="search.html", title="Hytale Names | Search result",
                           description=DESCRIPTION,
                           keywords=KEYWORDS,
                           logged_in=True if session.get("logged_in") else False)

# Done.
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect("/")
    if request.method == 'POST':
        if (request.form.get('email') and request.form.get('passwd')):
            email = request.form.get('email')
            passwd = request.form.get('passwd')
            if (re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email)):
                user = get_user(hash_passwd(passwd), email)
                if user:
                    session['logged_in'] = True
                    session['id'] = user[0]
                    session['logged_in'] = True
                    session['email'] = user[2]
                    session['username'] = user[1]
                    session['registred'] = user[4]

                    session['recover'] = user[5]
                    return redirect("/")
                else:
                    flash("Email or password are wrong.")
            else:
                flash("Invalid email.")
        else:
            flash("Something went wrong!")

    return render_template("layout.html", page="login.html", title="Hytale Names | Log In",
                           description=DESCRIPTION,
                           keywords=KEYWORDS,
                           logged_in=True if session.get("logged_in") else False)

# Done.
@app.route("/logout", methods=["GET", "POST"])
def logout():
    if session.get('logged_in'):
        session['logged_in'] = False
        return redirect("/")
    else:
        return "error", 404

# Done.
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("logged_in"):
        return redirect("/")
    if request.method == 'POST':
        if checkRecaptcha(request.form.get('g-recaptcha-response'), GOOGLE_RECAPTCH_V2_SECRET_KEY):
            USERNAME = request.form.get("username")
            EMAIL = request.form.get("email")
            PASSWD = request.form.get("passwd")
            CONFIRM_PASS = request.form.get("confirm")
            if request.form.get("privacyConsent") and request.form.get("oldEnough"):
                if (len(USERNAME) > 3 and len(USERNAME) < 30) and (len(EMAIL) > 5 and len(EMAIL) < 30):
                    if (len(PASSWD) > 8 and len(PASSWD) < 30):
                        if (re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", EMAIL)):
                            if (not get_email(EMAIL)):
                                if (PASSWD == CONFIRM_PASS):
                                    if re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', PASSWD):
                                        store_user(USERNAME, EMAIL, PASSWD)
                                        HASH = str(random.getrandbits(256))
                                        text = "Thank you for your sign up, here is your link for confirmation:\nhttps://hytalenames.org/confirm?hash={}".format(
                                            HASH)
                                        send_mail(EMAIL, "Recover Password", text)
                                        save_recover_hash(HASH, EMAIL)
                                        session['logged_in'] = True
                                        session['registred'] = False
                                        session['logged_in'] = True
                                        session['email'] = EMAIL
                                        session['username'] = USERNAME

                                        session['recover'] = HASH
                                        return redirect("/")
                                    else:
                                        flash("password must contain Uppercase, lowercase, numbers and special characters.")
                                else:
                                    flash("password and confirmation password aren't identical.")
                            else:
                                flash("email already exist.")
                        else:
                            flash("Invalid email")
                    else:
                        flash("password must be atleast 8 characters.")
                else:
                    flash("short username or email.")
            else:
                flash("please read and accept the terms of services.")
        else:
            flash("please make sure to check the recaptcha box")

    return render_template("layout.html", page="signup.html", title="Hytale Names | Sign up", description=DESCRIPTION,
                    keywords=KEYWORDS,
                    logged_in=True if session.get("logged_in") else False)


# Done.
@app.route("/forget-password", methods=["GET", "POST"])
def forget_pass():
    if session.get("logged_in"):
        return redirect("/")

    if request.method == 'POST':
        if request.form.get("email"):
            EMAIL = request.form.get("email")
            if (re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", EMAIL)):
                if get_email(EMAIL):
                    HASH = str(random.getrandbits(256))
                    text = "You have requested a password recovering, thats your recovering link:\nhttps://hytalenames.org/recover?hash={}".format(HASH)
                    send_mail(EMAIL, "Recover Password",text)
                    save_recover_hash(HASH, EMAIL)
                    return redirect("/check-mail")
                else:
                    flash("email doesn't exist")
            else:
                flash("Invalid email")

    return render_template("layout.html", page="forget-password.html", title="Hytale Names | Recover account",
                           description=DESCRIPTION,
                           keywords=KEYWORDS,
                           logged_in=True if session.get("logged_in") else False)


# Progress
@app.route("/recover", methods=["GET", "POST"])
def recover():
    if session.get("logged_in"):
        return redirect("/")

    if request.method == 'POST':
        PASSWD = request.form.get("passwd")
        CONFIRM_PASS = request.form.get("confirm")
        HASH = request.form.get("hash")
        if (len(PASSWD) > 8 and len(PASSWD) < 30):
            if (PASSWD == CONFIRM_PASS):
                if re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', PASSWD):
                    update_password(HASH, hash_passwd(PASSWD))
                    session['logged_in'] = True
                    session['registred'] = True
                    return redirect("/profile-updated")

    if request.args.get("hash"):
        HASH = request.args.get("hash")
        if HASH.stript().isnumeric():
            user = get_user_recover(HASH)
            if user:
                session['id'] = user[0]
                session['logged_in'] = True
                session['email'] = user[2]
                session['username'] = user[1]
                session['registred'] = user[4]
                session['recover'] = user[5]
                return render_template("layout.html", page="creat_password.html", hash=HASH)

            else:
                return "error", 404
        else:
            return "error", 404

    return redirect("/")

# Done.
@app.route("/confirm", methods=["GET"])
def confirm():
    if session.get("logged_in"):
        return redirect("/")

    if request.args.get("hash"):
        HASH = request.args.get("hash")
        if HASH.stript().isnumeric():
            user = get_user_recover(HASH)
            if user:
                session['logged_in'] = True
                session['registred'] = True
                register_user(user[0])
                session['id'] = user[0]
                session['email'] = user[2]
                session['username'] = user[1]
                session['recover'] = user[5]
                return redirect("/")
            else:
                return "error", 404

    return redirect("/")


# TODO
@app.route("/claim-your-profile")
def claim():
    return "Comming Soon..<script>document.ready(window.setTimeout(location.href = \"https://hytalenames.org\",7000));</script>"


# Important note here
@app.route("/profile-updated")
def profile_updated():
    if not session.get("logged_in"):  # change if session.get("logged_in") to if not session.get("logged_in")
        return redirect("/")
    return render_template("layout.html", page="profile-updated.html", title="Hytale Names | Profile updated",
                           description=DESCRIPTION,
                           keywords=KEYWORDS,
                           logged_in=True if session.get("logged_in") else False)

@app.route("/check-mail")
def check_mail():
    if session.get("logged_in"):
        return redirect("/")
    flash("An email has been sent, please check your email address.")
    return redirect("/")


@app.route("/hytale-names")
def hytale_names():
    results = get_favorit_names()

    page = 1
    m = (len(results) // 10) + 1
    if request.args.get("p"):
        if len(results) > 10:
            page = int(request.args.get("p") if request.args.get("p").strip().isnumeric() else 1)
            if page <= m and page > 0:
                results = results[10*(page-1): page*10]
            else:
                page = 1

    return render_template("layout.html", best_names=results, m=m, p=page, page="hytale-names.html", title="Hytale Names | Names List",
                           description=DESCRIPTION,
                           keywords=KEYWORDS)

# Done
@app.route("/discord")
def discord():
    return redirect("https://discord.gg/Aue4hEt")

@app.route("/names/like/", methods=["GET", "POST"])
def like():
    if request.method == 'POST':
        if request.form.get("id"):
            id = request.form.get("id").strip()
            if not check_ip_like(request.remote_addr, id):
                session['liked'+str(id)] = True
                return jsonify(success="Liked", id=id)
            else:
                session['liked' + str(id)] = False
                return jsonify(success="Unliked", id=id)


    return jsonify({"success": "method not allowed"}), 404

@app.route("/send-again", methods=["GET", "POST"])
def send_again():
    if request.method == 'POST':
        if checkRecaptcha(request.form.get('g-recaptcha-response'), GOOGLE_RECAPTCH_V2_SECRET_KEY):
            if not session['registred'] and session['logged_in']:
                text = "Thank you for your sign up, here is your link for confirmation:\nhttps://hytalenames.org/confirm?hash={}".format(
                    session['recover'])
                send_mail(session['email'], "Recover Password", text)
                return redirect("/")

    return render_template("layout.html", page="send-again.html", title="Hytale Names | Send again",
                           description=DESCRIPTION,
                           keywords=KEYWORDS)

if __name__ == "__main__":
    app.secret_key = 'SESSION SECRET'
    app.run()