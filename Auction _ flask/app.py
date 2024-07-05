from flask import Flask, request, render_template, session, redirect, url_for
from flask_bcrypt import Bcrypt
import jwt
from flask_login import LoginManager, login_user, current_user, login_required, UserMixin, logout_user
from flask import flash
from models import db, User, Auction, Bid
from datetime import datetime
import secrets
from flask_session import Session
from functools import wraps

secret_key = secrets.token_hex(32)

app = Flask(__name__)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auction.db'

app.config['SECRET_KEY'] = secret_key
app.config['SESSION_TYPE'] = 'filesystem'  
app.config['SESSION_USE_SIGNER'] = True   
app.config['SESSION_KEY_PREFIX'] = 'auction_app_'  

db.init_app(app)
with app.app_context():
    db.create_all()
Session(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('landing_page'))
        return view_func(*args, **kwargs)
    return wrapped_view

@app.route("/")
def landing_page():
    is_landing_page = True  
    
    return render_template('index.html', is_landing_page=is_landing_page)

@app.route('/register', methods=['GET', 'POST'])
def register():
    is_landing_page = True 
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

       
        if not username or not email or not password:
            return render_template('register.html', error='Invalid input', is_landing_page=is_landing_page)

        
        existing_user = User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first()
        if existing_user:
            return render_template('register.html', error='Username or email already exists', is_landing_page=is_landing_page)

        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

       
        user = User(username=username, email=email, password=hashed_password)

        
        db.session.add(user)
        db.session.commit()

        return render_template('login.html', message='User registered successfully')

    return render_template('register.html', is_landing_page=is_landing_page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    is_landing_page = True 
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')
        
        # Find user by username
        user = User.query.filter_by(username=username).first()

        if not user:
            flash('Username not found', 'error')
            return render_template('login.html', is_landing_page=is_landing_page)

      
        if not bcrypt.check_password_hash(user.password, password):
            flash('Invalid username or password', 'error')
            return render_template('login.html', is_landing_page=is_landing_page)

      
        access_token = generate_access_token(user.username)

        session['username'] = user.username
        session['user_id'] = user.id  
        session['access_token'] = access_token
        login_user(user)
        
        return redirect(url_for('profile'))

    return render_template('login.html', is_landing_page=is_landing_page)


@app.route('/auctions', methods=['GET', 'POST'])
@login_required
def auctions():
    if request.method == 'POST':
        data = request.form
        title = data.get('title')
        description = data.get('description')
        initial_bid = data.get('initial_bid')
        end_date = data.get('end_date')

        end_date = datetime.fromisoformat(end_date.replace('T', ' '))
        
        if not title or not initial_bid or not end_date:
            return render_template('create_auction.html', error='Invalid input')

        
        auction = Auction(title=title, description=description, initial_bid=initial_bid, end_date=end_date, user_id=current_user.id)
       
        db.session.add(auction)
        db.session.commit()

        return render_template('create_auction.html', message='Auction created successfully')

    return render_template('create_auction.html')

@app.route('/profile')
@login_required
def profile():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            user_auctions = Auction.query.filter_by(user_id=user.id).all()
            return render_template('profile.html', access_token=session.get('access_token'), username=username, user_auctions=user_auctions)
    return render_template('profile.html', access_token=session.get('access_token'))

@app.route('/auction', methods=['GET'])
@login_required
def list_auctions():
    auctions = Auction.query.all()
    return render_template('list_auctions.html', auctions=auctions)

@app.route('/place_bid/<int:auction_id>', methods=['GET', 'POST'])
@login_required
def place_bid(auction_id):
    auction = Auction.query.get(auction_id)
    
    
    if 'username' not in session:
        
        return redirect(url_for('login', auction_id=auction_id))
    
   
    user_id = session['user_id']
    
    if not auction:
        return render_template('place_bid.html', error='Auction not found', description=auction.description)

    highest_bid = Bid.query.filter_by(auction_id=auction_id).order_by(Bid.amount.desc()).first()

    if request.method == 'POST':
        bid_amount = request.form.get('bid_amount')

        if not bid_amount or float(bid_amount) <= auction.initial_bid:
            return render_template('place_bid.html', auction_id=auction_id, error='Invalid bid amount', description=auction.description)

        if highest_bid and float(bid_amount) <= highest_bid.amount:
            return render_template('place_bid.html', auction_id=auction_id, error='Bid amount must be higher than the current highest bid', description=auction.description)
        
        # Create bid object
        bid = Bid(auction_id=auction_id, user_id=user_id, amount=bid_amount)

        # Store bid data
        db.session.add(bid)
        db.session.commit()

        return render_template('place_bid.html', auction_id=auction_id, user_id=user_id, description=auction.description)

    return render_template('place_bid.html', auction_id=auction_id, user_id=user_id,description=auction.description)

@app.route('/auctions/<int:auction_id>', methods=['GET', 'POST'])
@login_required
def update_auction(auction_id):
    auction = Auction.query.get(auction_id)
    if not auction:
        return render_template('update_auction.html', error='Auction not found')

    if request.method == 'POST':
        data = request.form
        auction.title = data['title']
        auction.description = data['description']
        end_date_str = data['end_date']
        end_date = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')

        auction.end_date = end_date
        db.session.commit()

        return render_template('update_auction.html', auction=auction, auction_id=auction_id, message='Auction updated successfully')

    return render_template('update_auction.html', auction=auction, auction_id=auction_id)

@app.route('/auctions/<int:auction_id>/delete', methods=['POST', 'DELETE'])
@login_required
def delete_auction(auction_id):
    if request.method == 'POST' or request.method == 'DELETE':
        auction = Auction.query.get(auction_id)
        if not auction:
            return render_template('delete_auction.html', error='Auction not found')

        db.session.delete(auction)
        db.session.commit()

        return render_template('delete_auction.html', message='Auction deleted successfully')
    
    
@app.route('/logout')
def logout():
    session.clear()

    return redirect(url_for('landing_page'))


def generate_access_token(username):
    payload = {'username': username}
    access_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return access_token

if __name__ == '__main__':
    app.run(debug=True)