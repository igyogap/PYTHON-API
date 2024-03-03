from flask import Flask, request, make_response, jsonify
from flask_restful import Resource, Api
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

# Library pendukung
import jwt
import os
import datetime
import hashlib

# installasi project flask
app = Flask(__name__)
api = Api(app)
CORS(app)


# Config to Database
filename = os.path.dirname(os.path.abspath(__file__))
database = 'sqlite:///' + os.path.join(filename, 'db.sqlite')
app.config['SQLALCHEMY_DATABASE_URI'] = database
db = SQLAlchemy(app)

# konfigurasi secreet key
app.config["SECRET_KEY"] = "kuncirahasia"

# Model (Login Register)
class AuthModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(128))
    
class AppModel(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    judul = db.Column(db.String(100))
    
# Create Database to file sqlite
with app.app_context():
    db.create_all()

# Create decorator
def get_token(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return make_response(jsonify({"msg":"Token kosong"}),401)
        try:
            jwt.decode(token, app.config["SECRET_KEY"], algorithms=['HS256'])
        except Exception as r:
            print(r)
            return make_response(jsonify({"msg":"Token Salah"}),401)
            
        return f(*args, **kwargs)
    return decorator


# Hashing password
def hash_password(password):
    # Create a new SHA-256 hash object
    sha256 = hashlib.sha256()

    # Update the hash object with the password bytes
    sha256.update(password.encode('utf-8'))

    # Get the hexadecimal representation of the hash
    hashed_password = sha256.hexdigest()

    return hashed_password

# Verify password 
def verify_password(entered_password, stored_hashed_password):
    # Hash the entered password
    entered_password_hashed = hash_password(entered_password)

    # Compare the entered hashed password with the stored hashed password
    return entered_password_hashed == stored_hashed_password
    
# Create Routing endpoint Register
class RegisterUser(Resource):
    def post(self):
        dataUsername = request.form.get('username')
        dataPassword = request.form.get('password')
        
        # hash password
        password_hasing = hash_password(dataPassword)
        
        # validasi data
        if dataUsername and dataPassword:
            # tulis data ke db.sqllite
            dataModel = AuthModel(username = dataUsername, password = password_hasing)
            db.session.add(dataModel)
            db.session.commit()
            return make_response(jsonify(success = True), 200)
        return make_response(jsonify({"msg":"gagal"}))

# Create Routing endpoint Login     
class LoginUser(Resource):
    def post(self):
        dataUsername = request.form.get('username')
        dataPassword = request.form.get('password')
        
        # Validasi data
        # query = AuthModel.query.all() # list
        queryUsername = [data.username for data in AuthModel.query.all()] # list
        
        # Check Username and password
        if dataUsername in queryUsername:
            verify_Users = AuthModel.query.filter_by(username=dataUsername).first()
            if verify_password(dataPassword, verify_Users.password):
                token = jwt.encode({"username":dataUsername, "exp":datetime.datetime.utcnow()+datetime.timedelta(minutes=10)},app.config["SECRET_KEY"], algorithm="HS256")
            
                return make_response(jsonify({"msg":"Login Sukses","token":token}),200)
            return jsonify({"msg":"password  salah!"})
        return jsonify({"msg":"uname not found"})

class Content(Resource):
    @get_token
    def get(self):
        return make_response(jsonify({"msg":"Hello world"}))

    
# Inisiasi resurce API
api.add_resource(RegisterUser, "/api/register", methods=["POST"])
api.add_resource(LoginUser, "/api/login", methods=["POST"])
api.add_resource(Content, "/api/content", methods=["GET"])

# Jalankan applikasi app.py
if __name__ == "__main__":
    app.run(debug=True)