from flask import Flask,request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from flask_marshmallow import Marshmallow



app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
db = SQLAlchemy(app)
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)
ma = Marshmallow(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, unique=False, nullable=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, unique=True, nullable=False)
    body = db.Column(db.String, unique=True, nullable=False)
# db.create_all()

class UserSchema(ma.Schema):
    class Meta:
        # Fields to expose
        fields = ("username",)

    # # Smart hyperlinking
    # _links = ma.Hyperlinks(
    #     {
    #         "self": ma.URLFor("user_detail", values=dict(id="<id>")),
    #         "collection": ma.URLFor("users"),
    #     }
    # )


user_schema = UserSchema()
users_schema = UserSchema(many=True)


@app.route('/')
def hh():
    return {'message':"hello"}

@app.route('/register',methods=['POST'])
def register():
    args=request.get_json()
    
    try:
        username=args.get('username')
        password=args.get('password')
        db.session.add(User(username=username,password=password))
        db.session.commit()
        return {'message':'registered'},201
    except Exception as e:
        return{'message':e},500


@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    user=User.query.filter_by(username=username).first()
    if user.username==username and user.password==password:

        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify(message="username or password is wrong "), 400

@app.route("/all-users",methods=['POST'])
def allUsers():
    users=User.query.all()
    
    return jsonify(AllUser=users_schema.dump(users)),200