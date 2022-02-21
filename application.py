import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get user's current asset information
    usercash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0].get('cash')
    totalassets = usercash
    stocks = db.execute("SELECT * FROM stocks WHERE userid = ?", session["user_id"])

    # Create list of stocks
    for stock in stocks:
        currentprice = float(lookup(stock['symbol']).get('price'))
        totalvalue = stock['shares'] * currentprice
        db.execute("UPDATE stocks SET currentprice = ?, assetvalue = ? WHERE userid = ? AND symbol = ?",
                   currentprice, totalvalue, session["user_id"], stock['symbol'])
        totalassets = totalassets + totalvalue

    return render_template("index.html", stocks=stocks, cash=usercash, totalassets=totalassets)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route by submitting quote form
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 403)

        stock = lookup(request.form.get("symbol"))

        # Ensure symbol is valid
        if not stock:
            return apology("invalid stock symbol", 403)

        # Ensure user has enough money for purchase
        price = stock.get('price')
        shares = request.form.get('shares')
        cost = float(shares) * price
        usercash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0].get('cash')

        if cost > usercash:
            return apology("Not enough money for purchase", 403)

        # update user's cash and transaction history
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", cost, session["user_id"])
        db.execute("INSERT INTO transactionhistory (userid, symbol, price, shares, action, timestamp) \
            VALUES(?, ?, ?, ?, ?, ?)", session["user_id"], stock.get('symbol'), price, shares, "Bought", datetime.now())

        if not db.execute("SELECT symbol FROM stocks WHERE userid = ? AND symbol = ?", session["user_id"], stock.get('symbol')):
            db.execute("INSERT INTO stocks (userid, symbol, company, shares, currentprice, assetvalue) \
            VALUES(?, ?, ?, ?, ?, ?)", session["user_id"], stock.get('symbol'), stock.get('name'), shares, price, cost)

        else:
            db.execute("UPDATE stocks SET shares = shares + ? WHERE userid = ? AND symbol = ?",
                       shares, session["user_id"], stock.get('symbol'))

        # Success message
        flash("Purchase Successful!")

        # Redirect user to home page
        return redirect("/")

    # User reached route by clicking "Quote"
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get user's current transaction history
    transactions = db.execute("SELECT * FROM transactionhistory WHERE userid = ?", session["user_id"])

    usercash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0].get('cash')
    return render_template("history.html", transactions=transactions, cash=usercash)


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

    # User reached route by submitting quote form
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 403)

        stock = lookup(request.form.get("symbol"))

        # Ensure symbol is valid
        if not stock:
            return apology("invalid stock symbol", 403)

        # Redirect user to quoted page
        return render_template("quoted.html", company=stock.get('name'), symbol=stock.get('symbol'), price=stock.get('price'))

    # User reached route by clicking "Quote"
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget user id
    session.clear()

    # User reached route by submitting register form
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmed = request.form.get("passwordconfirm")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password is sufficiently strong
        # Digit check from Stack Overflow user "thefourtheye" at https://stackoverflow.com/questions/19859282/check-if-a-string-contains-a-number
        if len(password) < 5 or not any(char.isdigit() for char in password):
            return apology("Password must be at least 5 characters and include a number", 403)

        # Ensure password was submitted and confirmed
        if not password or not confirmed:
            return apology("must provide and confirm password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and passwords match
        if len(rows) > 0 or not password == confirmed:
            return apology("invalid username and/or password", 403)

        # Store username and password
        passhash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, passhash)

        # Remember which user has registered
        session["user_id"] = db.execute("SELECT id FROM users WHERE username = ?", username)[0].get('id')

        # Success message
        flash("Successfully registered!")

        # Redirect user to home page
        return redirect("/")

    # User reached route by clicking "Register"
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route by submitting quote form
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 403)

        stock = lookup(request.form.get("symbol"))

        # Ensure symbol is valid
        if not stock:
            return apology("invalid stock symbol", 403)

        # Ensure user owns the stock
        if not db.execute("SELECT symbol FROM stocks WHERE symbol = ?", stock.get('symbol')):
            return apology("You don't own any shares of that stock", 403)

        price = stock.get('price')
        shares = request.form.get('shares')
        cost = float(shares) * price
        currentshares = db.execute("SELECT shares FROM stocks WHERE userid = ? AND symbol = ?",
                                   session["user_id"], stock.get('symbol'))[0].get('shares')
        usercash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0].get('cash')

        # Ensure user owns enough of the stock
        if currentshares < int(shares):
            return apology("You don't own that many shares of that stock", 403)

        # update user's cash and transaction history
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", cost, session["user_id"])
        db.execute("INSERT INTO transactionhistory (userid, symbol, price, shares, action, timestamp) \
            VALUES(?, ?, ?, ?, ?, ?)", session["user_id"], stock.get('symbol'), price, shares, "Sold", datetime.now())
        if currentshares == int(shares):
            db.execute("DELETE FROM stocks WHERE symbol = ? AND userid = ?", stock.get('symbol'), session['user_id'])
        db.execute("UPDATE stocks SET shares = shares - ? WHERE userid = ? AND symbol = ?",
                   shares, session["user_id"], stock.get('symbol'))

        # Success message
        flash("Sale Successful!")

        # Redirect user to home page
        return redirect("/")

    # User reached route by clicking "Quote"
    else:
        # Get user's stock holdings
        stocks = db.execute("SELECT * FROM stocks WHERE userid = ?", session["user_id"])

        return render_template("sell.html", stocks=stocks)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Add money to account"""
    # User reached route by submitting quote form
    if request.method == "POST":

        addcash = float(request.form.get("amount"))
        # Error checking
        if not addcash:
            return apology("must enter amount to add", 403)

        if addcash > 10000:
            return apology("You can only add $10 000 at one time", 403)

        # Update amount of cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", addcash, session["user_id"])

        # Create transaction
        db.execute("INSERT INTO transactionhistory (userid, symbol, price, shares, action, timestamp) \
            VALUES(?, ?, ?, ?, ?, ?)", session["user_id"], "", addcash, "", "Cash Added", datetime.now())

        # Success message
        flash("Cash added!")

        # Redirect user to home page
        return redirect("/")

    # User reached route by clicking "Quote"
    else:
        return render_template("add.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
