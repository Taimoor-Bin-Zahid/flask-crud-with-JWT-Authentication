from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import re
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']= 'mysql://root:@localhost/pyjwtdatabase'
app.config['JWT_SECRET_KEY'] = 'My_Secret_key'
db = SQLAlchemy(app)
jwt = JWTManager(app)
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80), unique=True, nullable=False)
    email= db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), unique=False, nullable=False)



db.create_all()

@app.route('/createUser', methods=['POST'])

def createUser():

    data = request.get_json()
    user_name = data.get('user_name')
    password = data.get('password')
    email = data.get('email')


    if not user_name or not password or not email:
        return jsonify({'message': 'Missing username or password or email'}), 400
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'error': 'Invalid email format'}), 400
    # password = str(password)
    # password = password.encode('utf-8')
    # hashed_password = bcrypt.hashpw(password, bcrypt.gensalt(10))

    matchPassword = password
    
    passwordTemp = matchPassword.encode('utf-8')
    hashed_password = bcrypt.hashpw( passwordTemp, bcrypt.gensalt(10))


    new_email = Users.query.filter_by(email=email).first()
    if new_email:
        return jsonify({'message': 'Email already in use, please use different email!'}), 400
    
    #password = Users.query.filter_by(password=password).first()
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400
    if ' ' in password:
        return jsonify({'error': 'Password cannot contain spaces'}), 400
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return jsonify({'error': 'Password must contain at least one special character'}), 400
    if not re.search(r"[a-z]", password):
        return jsonify({'error': 'Password must contain at least one lowercase letter'}), 400
    if not re.search(r"[A-Z]", password):
        return jsonify({'error': 'Password must contain at least one uppercase letter'}), 400
    

    user = Users.query.filter_by(user_name=user_name).first()
    if user:
        return jsonify({'message': 'Username already exists, please use another name!'}), 409


    new_user = Users(user_name=user_name, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201
@app.route('/getAllUsers', methods=['GET'])
def getAllUsers():
    users = Users.query.all()
    user_list = []
    for user in users:
        user_data = {
            'id': user.id,
            'user_name': user.user_name,
            'email': user.email,
            'password': user.password
        }

        user_list.append(user_data)
    return jsonify({'users': user_list}), 200

@app.route('/getUserById/<int:id>', methods=['GET'])
def get_user_by_id(id):
    print(id)
    user = Users.query.get(id)
    if user is None:
        return jsonify({'error': 'User not found'}), 404

    user_data = {
        'id': user.id,
        'user_name': user.user_name,
        'email': user.email
    }
    return jsonify({'user': user_data})

@app.route('/userLogin', methods=['POST'])
def userLogin():
    email = request.json.get('email')
    password = request.json.get('password')
    user = Users.query.filter_by(email=email).first()

    print("Hashed password here -> ",user.password)

    #if user and bcrypt.checkpw(password, user.password.encode('utf-8')):
    print(user.password)
    if user and password==password:
        access_token = create_access_token(identity=user.id), 200
        return jsonify({'Successfully logged in your access_token is:': access_token, 'user id': user.id }), 200
    else:
        return jsonify({'error': 'We fail'}), 400

@app.route('/protected')
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    return jsonify({'message': 'Access granted to protected route', 'user_id': current_user_id})

@app.route('/userDelete/<int:user_id>', methods=['DELETE'])
@jwt_required()
def userDelete(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 404
    user = Users.query.get(user_id)

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    else:
        return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)