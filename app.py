
from email.policy import default
from flask import Config, Flask, jsonify, make_response, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from idna import check_hyphen_ok
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import traceback
from flask_migrate import Migrate
from auth.controllers.auth_controller import AUTH

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123456@localhost/blog'
app.config['SECRET_KEY'] = 'secretKey'


db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

app.register_blueprint(AUTH, url_prefix='/')
"""
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(40))
    lname = db.Column(db.String(40))
    email = db.Column(db.String(40))
    is_admin = db.Column(db.Boolean, default=False)
    password = db.Column(db.String(200))

    def __init__(self, fname, lname, email, password):
        self.fname = fname
        self.lname = lname
        self.email = email
        self.password = password


class Blog(db.Model):
    __tablename__ = "blogs"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    likes = db.relationship('Like', backref=db.backref('blogs', lazy=True))

    def __init__(self, text, user_id):
        self.text = text
        self.user_id = user_id


class Like(db.Model):
    __tablename__ = "likes"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id', ondelete="CASCADE"))
    blog_id = db.Column(db.Integer, db.ForeignKey(
        'blogs.id', ondelete="CASCADE"))


@app.route('/')
@token_required
def index(current_user):
    print(current_user.is_admin)
    return "Hello Weird"


@app.route('/submit', methods=['POST'])
def submit():
    if request.method == "POST":
        fname = request.form['fname']
        lname = request.form['lname']
        email = request.form['email']
        password = generate_password_hash(
            request.form['password'], method='sha256')

        user = User(fname, lname, email, password)
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': '.New User created'})

    return "Submit"


@app.route('/login', methods=['POST'])
def login():

    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):

        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = User.query.filter_by(email=auth.get('email')) .first()

    password = request.form['password']
    if user:
        if check_password_hash(user.password, password):
            token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow(
            ) + datetime.timedelta(minutes=30000)}, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({'token': token})

    print("Invalid identity")
    return "Invalid identity "

    # Use conditions to compare the authenticating password with the stored one:

"""


@app.route('/blog', methods=['GET'])
@token_required
def get_all_blogs(current_user):
    items = []
    for item in db.session.query(Blog).all():
        del item.__dict__['_sa_instance_state']
        items.append(item.__dict__)
    return jsonify(items)


@app.route('/blog/<blog_id>', methods=['GET'])
@token_required
def get_one_blog(current_user, blog_id):
    if(request.method == "GET"):
        items = []
        for item in Blog.query.filter_by(id=blog_id).all():
            del item.__dict__['_sa_instance_state']
            items.append(item.__dict__)
        print(items)
        return jsonify(items)


@app.route('/blog/user/<user_id>', methods=['GET'])
@token_required
def get_one_user_blogs(current_user, user_id):
    items = []
    for item in Blog.query.filter_by(user_id=user_id).all():
        del item.__dict__['_sa_instance_state']
        items.append(item.__dict__)
    return jsonify(items)


@app.route('/write', methods=['POST'])
@token_required
def create_blog(current_user):
    text = request.form['text']

    blog = Blog(text, user_id=current_user.id)
    db.session.add(blog)
    db.session.commit()

    return jsonify({'message': 'Blog created!'})


@app.route('/blog/<blog_id>', methods=['PUT'])
@token_required
def edit_blog(current_user, blog_id):
    blog = Blog.query.filter_by(id=blog_id).first()
    if(current_user.id == blog.user_id or current_user.is_admin == True):
        text_updated = request.form['text']
        db.session.query(Blog).filter_by(id=blog_id).update(
            dict(text=text_updated)
        )
        blog = Blog.query.filter_by(id=blog_id)
        db.session.commit()
        print(blog)
    else:
        return "Your not authorized!!"
    return 'blog'


@app.route('/blog/<blog_id>', methods=['DELETE'])
@token_required
def delete_blog(current_user, blog_id):
    blog = Blog.query.filter_by(id=blog_id).first()
    if(current_user.id == blog.user_id or current_user.is_admin == True):
        db.session.query(Blog).filter_by(id=blog_id).delete()
        db.session.commit()
        return "Succesfully deleted!"
    else:
        return "Your not authorized!!"


@app.route("/blog-like/<blog_id>", methods=['GET'])
@token_required
def like(current_user, blog_id):
    blog = Blog.query.filter_by(id=blog_id)
    like = Like.query.filter_by(
        user_id=current_user.id, blog_id=blog_id).first()

    if not blog:
        return "Blog doesnt exist"
    elif like:
        db.session.delete(like)
        db.session.commit()
    else:
        like = Like(user_id=current_user.id, blog_id=blog_id)
        db.session.add(like)
        db.session.commit()

    return "Likes"


@app.route("/blog-like/blogs/<blog_id>", methods=['GET'])
@token_required
def like_blogs(current_user, blog_id):
    items = []
    for item in Like.query.filter_by(blog_id=blog_id).all():
        del item.__dict__['_sa_instance_state']
        items.append(item.__dict__)
    return jsonify(items)


@app.route("/blog-like/users/<user_id>", methods=['GET'])
@token_required
def like_users(current_user, user_id):
    items = []
    for item in Like.query.filter_by(user_id=user_id).all():
        del item.__dict__['_sa_instance_state']
        items.append(item.__dict__)
    return jsonify(items)


if __name__ == "__main__":
    app.run(debug=True)
