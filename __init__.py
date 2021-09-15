from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import json
import requests
import time
from datetime import datetime
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from random import randint

# NON PRODUCTION VERSION, PROVIDE FEEDBACK IF NEEDED. PLEASE FOLLOW PEP8 TYPING GUIDELINES IF YOU ARE EDITING THIS! (originally created for another developer to finish, e.g optimize, stop bugs and rename variables)
# CONFIG
# CONFIG WILL BE MOVED TO A SEPARATE FILE WHEN PUSHED FOR BLUEPRINTING!
app = Flask(__name__)
app.config["SECRET_KEY"] = "changethisondeployment."
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
paymentapi = "your key here"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    verify = db.Column(db.String(5))
    # verified is the email verification flag, 0 is not verified. 1 is verified by email.
    verified = db.Column(db.Integer)
    perm = db.Column(db.Integer)
    bal = db.Column(db.Integer)
    referall = db.Column(db.String(15))


class Servers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    server = db.Column(db.String(50))
    price = db.Column(db.Integer)
    hash = db.Column(db.Integer)
    dprofit = db.Column(db.String(50))
    expire = db.Column(db.Integer)
    expire_d = db.Column(db.String(50))


class ServersType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    picture = db.Column(db.String(50))
    server = db.Column(db.String(50))
    price = db.Column(db.Integer)
    hash = db.Column(db.Integer)
    dprofit = db.Column(db.Integer)


class Support(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50))
    username = db.Column(db.String(50))
    subject = db.Column(db.String(50))
    message = db.Column(db.String(500))


class Deposit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payment_id = db.Column(db.String(150))
    email = db.Column(db.String(50))
    username = db.Column(db.String(50))
    pay_address = db.Column(db.String(150))
    price_amount = db.Column(db.String(100))
    crypto = db.Column(db.String(50))
    crypto_amount = db.Column(db.String(50))
    status = db.Column(db.String(50))


class Withdrawl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    amount = db.Column(db.String(50))
    currency = db.Column(db.String(50))
    wallet = db.Column(db.String(50))
    status = db.Column(db.String(50))
    date = db.Column(db.String(50))


class Codes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50))
    amount = db.Column(db.String(50))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.errorhandler(Exception)
def all_exception_handler(error):
    print(error)
    return "oops! looks like a error has occurred. check console logs!"


class LoginForm(FlaskForm):
    username = StringField(
        "username", validators=[InputRequired(), Length(min=4, max=15)]
    )
    password = PasswordField(
        "password", validators=[InputRequired(), Length(min=8, max=80)]
    )
    remember = BooleanField("remember me")


class VerifyForm(FlaskForm):
    email = StringField(
        "email",
        validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)],
    )
    verify = StringField("code", validators=[InputRequired(), Length(max=5)])


class RegisterForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)],
    )
    username = StringField(
        "Username", validators=[InputRequired(), Length(min=4, max=15)]
    )
    password = PasswordField(
        "Password", validators=[InputRequired(), Length(min=8, max=80)]
    )
    referall = StringField(
        "referall", validators=[Length(min=0, max=15)]
    )
    Confirm_password = PasswordField(
        "Confirm Password", validators=[InputRequired(), Length(min=8, max=80)]
    )
    terms = BooleanField("I accept the Terms and Conditions.")


# END OF CONFIG


@app.route("/")
def index():
    return redirect("/login")


# START OF LOGIN SECTION


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if check_password_hash(user.password, form.password.data):
                    if user.verified == 0:
                        return redirect("/verify")
                    else:
                        login_user(user, remember=form.remember.data)
                        return redirect("/dashboard")
        flash("invalid login!")
        return render_template("login.html", form=form)
    else:
        return render_template("login.html", form=form)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    # OTP mail verification, it was either this or a third party option.
    form = VerifyForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                if user.verify == form.verify.data:
                    try:
                        user.verified = 1
                        db.session.commit()
                        flash("email has been verified")
                        return redirect("login")
                    except:
                        flash("something went wrong, please try again.")
                        return render_template("verify.html", form=form)
                else:
                    flash("invalid code")
                    return render_template("verify.html", form=form)
        flash("invalid code or user")
        return render_template("verify.html", form=form)
    else:
        return render_template("verify.html", form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()
    if request.method == "POST":
        if form.validate_on_submit():
            if form.password.data != form.Confirm_password.data:
                flash("Passwords do not match.")
                return redirect(url_for("signup"))
            hashed_password = generate_password_hash(
                form.password.data, method="sha256"
            )
            # This is a form of OTP to sent via email, its unique per account and assigned upon register.
            value = randint(1000, 9999)
            print(form.referall.data)
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password,
                verify=str(value),
                verified=1,
                perm=0,
                bal=0,
                referall=form.referall.data
            )
            try:
                db.session.add(new_user)
                db.session.commit()
                return redirect("/login")
            except:
                db.session.rollback()
                flash(
                    "invalid: user already exists, or you did not fill in the proper parameters!"
                )
                return redirect(url_for("signup"))
        else:
            flash(
                "invalid: user already exists, or you did not fill in the proper parameters!"
            )
            return render_template("signup.html", form=form)
    else:
        return render_template("signup.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    # pops a user's session
    return redirect(url_for("index"))


# END OF LOGIN SECTION
@app.route("/dashboard")
@login_required
def dashboard():
    bal = current_user.bal
    username = current_user.username
    servers = Servers.query.filter_by(username=current_user.username)
    serverlist = servers.all()
    dprofit = 0
    for server in serverlist:
        dprofit += int(server.dprofit)
    for server in serverlist:
        expire = int(server.expire)
        current_date = int(time.time())
        if current_date > expire:
            Servers.query.filter_by(id=server.id).delete()
            db.session.commit()
            flash(f"your server has expired! {server.id}")
    return render_template(
        "dashboard.html",
        serverlist=serverlist,
        bal=bal,
        username=username,
        servercount=len(serverlist),
        dprofit=dprofit,
    )


@app.route("/shop")
@login_required
def shop():
    bal = current_user.bal
    username = current_user.username
    servertype = ServersType.query.all()
    return render_template(
        "shop.html", bal=bal, username=username, servertype=servertype
    )


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
        serv = request.args.get("server")
        bal = current_user.bal
        username = current_user.username
        servertype = ServersType.query.filter_by(server=serv)
        type = request.args.get("type")
        print(type)
        if type == "PURCHASE":
            serverlist = servertype.first()
            name = serverlist.server
            daily = int(serverlist.price)
            hash = serverlist.hash
            days = int(request.args.get("days"))
            code = request.args.get("code")
            final_price = 0
            if code != "":
                coupon = Codes.query.filter_by(code=code)
                coupon_obj = coupon.first()
                if coupon_obj is None:
                    flash(f"Discount Code failed.")
                    final_price += days * daily
                    return render_template(
                        "checkout.html", bal=bal, username=username, servertype=servertype
                    )
                else:
                    flash(f"Your discount code has been applied for ${coupon_obj.amount}!")
                    final_price += days * daily
                    discount = int(final_price) - int(coupon_obj.amount)
                    final_price = int(final_price)
            if code == "":
                final_price += days * daily
            if days < 7:
                flash("under the minimum amount of days.")
                return redirect("/shop")
            elif final_price > bal:
                flash("you do not have enough balance.")
                return redirect("/deposit")
            else:
                new_bal = bal - final_price
                current_user.bal = new_bal
                db.session.commit()
                expire = days * 86400
                current_date = int(time.time())
                new_expire = expire + current_date
                expire_d = datetime.fromtimestamp(new_expire).strftime("%m-%d-%Y")
                new_serv = Servers(
                    username=username,
                    server=name,
                    price=daily,
                    hash=serverlist.hash,
                    dprofit=serverlist.dprofit,
                    expire=new_expire,
                    expire_d=expire_d
                )
                db.session.add(new_serv)
                db.session.commit()
                flash("New server purchased!")
                return redirect("/dashboard")
        else:
            return render_template(
                "checkout.html", bal=bal, username=username, servertype=servertype
            )


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    if request.method == "POST":
     try:
       print(request.form)
       bal = current_user.bal
       username = current_user.username
       deposit = request.form["deposit"]
       currency = request.form["currency"]
       headers = {
            'x-api-key': f'{paymentapi}',
            'Content-Type': 'application/json',
        }
       data = '{ "price_amount": %s, "price_currency": "usd", "pay_currency": "%s", "ipn_callback_url": "https://nowpayments.io", "order_id": "RGDBP-21314", "order_description": "Apple Macbook Pro 2019 x 1" }' % (deposit, currency)
       response = requests.post('https://api.nowpayments.io/v1/payment', headers=headers, data=data)
       resp = json.loads(response.text)
       id = (resp['payment_id'])
       status = (resp['payment_status'])
       pay_address = (resp['pay_address'])
       price_amount = (resp['price_amount'])
       crypto = (resp['pay_currency'])
       crypto_amount = (resp['pay_amount'])
       deposit_request = Deposit(
           payment_id=id,
           email=current_user.email,
           username=username,
           pay_address=pay_address,
           price_amount=price_amount,
           crypto=crypto,
           crypto_amount=crypto_amount,
           status=status
       )
       db.session.add(deposit_request)
       db.session.commit()
       return redirect("/deposit")
     except:
         return redirect("/deposit")
    else:
        payment = request.args.get("payment")
        if payment != None:
            try:
                payment_search = Deposit.query.filter_by(payment_id=payment).all()
                for i in payment_search:
                    b = i.payment_id
                    headers = {
                        'x-api-key': f'{paymentapi}',
                    }
                    url = f'https://api.nowpayments.io/v1/payment/{b}'
                    response = requests.get(url, headers=headers)
                    resp = json.loads(response.text)
                    newstatus = (resp['payment_status'])
                    i.status = newstatus
                    db.session.commit()
                return redirect("/deposit")
            except:
                return redirect("/deposit")
        else:
            bal = current_user.bal
            username = current_user.username
            deposits = Deposit.query.filter_by(username=current_user.username)
            return render_template("deposit.html", bal=bal, username=username, deposits=deposits)


@app.route("/Withdraw", methods=["GET", "POST"])
@login_required
def withdraw():
    if request.method == "POST":
        try:
            print(request.form)
            bal = current_user.bal
            username = current_user.username
            wallet = request.form["wallet"]
            amount = request.form["amount"]
            currency = request.form["currency"]
            if int(amount) > int(bal) or len(wallet) < 10:
                flash("current balance is too low or invalid wallet!")
                return redirect("Withdraw")
            else:
                try:
                    withdraw_request = Withdrawl(
                        name=username,
                        amount=amount,
                        currency=currency,
                        wallet=wallet,
                        status="PENDING [ADMIN REVIEW]",
                        date="9"
                    )
                    db.session.add(withdraw_request)
                    db.session.commit()
                    flash("withdrawal request successfully added")
                    return redirect("Withdraw")
                except:
                    flash("DB ERROR: please try again in 5-10 minutes. contact support after 3 tries.")
                    db.session.rollback()
                    return redirect("Withdraw")
        except:
            flash(
                "invalid query: please make sure your wallet is correct and amount is a number."
            )
            return redirect("/withdraw")
    else:
        bal = current_user.bal
        username = current_user.username
        requests_withdrawl = Withdrawl.query.filter_by(name=current_user.username)
        return render_template(
            "withdraw.html", bal=bal, username=username, requests=requests_withdrawl
        )


@app.route("/index.html")
@login_required
def indexhtml():
    return redirect("/dashboard")


@app.route("/withdraw")
@login_required
def withdrawred():
    return redirect("/Withdraw")


@app.route("/Admin")
@login_required
def admin():
    perm = current_user.perm
    if perm == 1:
        users = User.query.all()
        rows = Servers.query.count()
        tol = 0
        for user in users:
            tol = user.bal
        return render_template("admin.html", servercount=rows, users=users, tol=tol)
    else:
        return redirect("/dashboard")


@app.route("/support", methods=['GET', 'POST'])
@login_required
def support():
    if request.method == "POST":
        subject = request.form["subject"]
        msg = request.form["message1"]
        username = current_user.username
        email = current_user.email
        if msg == "" or subject == "":
            flash("please fill in all fields!")
            return redirect("/support")
        try:
            support_ticket = Support(
                username=username,
                email=email,
                subject=subject,
                message=msg,
            )
            db.session.add(support_ticket)
            db.session.commit()
            flash("support ticket successfully sent! a member of staff will email you with the resolution")
            return redirect("/support")
        except Exception as E:
            print(E)
            flash("DB ERROR: please try again in 5-10 minutes. contact support after 3 tries.")
            db.session.rollback()
            return redirect("/support")
    else:
        bal = current_user.bal
        username = current_user.username
        return render_template("support.html", username=username, bal=bal)


@app.route("/info")
@login_required
def info():
    bal = current_user.bal
    username = current_user.username
    return render_template("info.html", username=username, bal=bal)


@app.route("/TOS")
def terms():
    try:
        bal = current_user.bal
        username = current_user.username
        return render_template("tos.html", username=username, bal=bal)
    except:
        return render_template("tos.html", username="Guest", bal="0")


@app.route("/FAQ")
@login_required
def FAQ():
    bal = current_user.bal
    username = current_user.username
    return render_template("faq.html", username=username, bal=bal)


if __name__ == "__main__":
    app.run(debug=False, port=80)  #SSL is handled by my CDN, cloudflare. hence the port 80
