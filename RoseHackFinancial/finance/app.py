import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
#AARYAN KUMAR
# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return apology("TODO")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        if request.form.get("apple")==0: #if the user didnt put anything in the box, could be "" or None instead of 0
            return apology("please fill in the symbol in the box")
        sauce = request.form.get("apple")
        cost = lookup(sauce)
        if not sauce:#if the cost is notfound in the search
            return apology("symbol not a real stock symbol")
        else:
            return render_template("quoted.html", quote=cost)
    else:#if the person uses GET instead
        return render_template("quote.html")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method=="POST":
        if request.form.get("code1")==0: #this would happen if the username was empty
            return apology("need username")
        #posibly elif not if, 0 might be""
        if request.form.get("code2")==0: #if password is not entered
            return apology("provide the password please")
        if request.form.get("code2check")==0: #if password confirm is not entered
            return apology("provide the conformation password please")
        if request.form.get("code2")!= request.form.get("code2check"): #if password and confirm are not the same
            return apology("provide provide the same confirmation password and password")
        checker = request.form.get("code1")
        answer = db.execute("SELECT username FROM users WHERE username== :checker", checker=checker)
        if checker == answer: #if username is already in the database
            return apology("username taken")
        if len(code2)<6:
            return apology("Password must be at least 6 letters long")
        lock = generate_password_hash(code2, method = "pbkdf2:sha256", salt_length = 6)#hashing the password
        db.execute("INSERT INTO users (username, hash) VALUES (:checker, :lock)", checker=checker, lock=lock)
        return redirect("/")
    else: #just in case the person tried getting in through GET
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
#656582896578





@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method=="post":
        if request.form.get("nameofstock")==0:
            return apology("enter stock symbol")
        if request.form.get("number")==0:
            return apology("enter number of stocks")
        positive=request.form.get("number")
        if positive<1:
            return apology("Need a positive number of stocks please. No hacking.")
        value = lookup(request.form.get("nameofstock"))
        if value == 0:#possibly none
            return apology("Not a valid stock name")
        neededmoney=value["price"]*request.form.get("number")
        currentmoney = db.execute("SELECT cash FROM users WHERE id=:keys", keys=session["user_id"])
        if currentmoney < neededmoney[0]["cash"]:
            return apology("Not enough money to buy that many stocks")




#AARYAN KUMAR

