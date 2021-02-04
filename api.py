import flask
from flask import request, jsonify
from flask_sqlalchemy import SQLAlchemy 
import uuid
import jwt 
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = flask.Flask(__name__)
app.config["DEBUG"] = True

app.config['SKEY'] ='sdfwasdgdaww423523wfsdSDFDSDF35'
app.config['SQLALCHEMY_DATABASE_URI']='mysql://admin:admin@localhost/user' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True 

db = SQLAlchemy(app)

class users(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    nme = db.Column(db.String(50))
    pwd= db.Column(db.String(50))
    no = db.Column(db.Integer)
    eml = db.Column(db.String(50))
    add = db.Column(db.String(50))

def token_required(f):  
    @wraps(f)  
    def decorator(*args, **kwargs):
       token = None 
       if 'x-access-tokens' in request.headers:  
          token = request.headers['x-access-tokens'] 
       if not token:  
          return jsonify({'message': 'a valid token is missing'})   
       try:  
          data = jwt.decode(token, app.config[SKEY]) 
          current_user = Users.query.filter_by(public_id=data['pid']).first()  
       except:  
          return jsonify({'message': 'token is invalid'})  
          return f(current_user, *args,  **kwargs)  
    return decorator 

@app.route('/', methods=['GET'])
def home():
    return '''<h1>Full stack developer test</h1>'''


@app.route('/api/signup', methods=['POST'])
def create_user():  
    data = request.get_json()  
    h_pwd = generate_password_hash(data['pwd'], method='sha256')
    new_user = users(pid=str(uuid.uuid4()), nme=data['nme'], pwd=h_pwd, no=data['no'], eml=data['eml'], add=data['add']) 
    db.session.add(new_user)  
    db.session.commit()    
    return jsonify({'msg': 'user created successfully'})   


@app.route('/api/login', methods=['GET', 'POST'])  
def login_user(): 
  auth = request.authorization   
  if not auth or not auth.nme or not auth.pwd:  
     return make_response('could not verify', 401, { "login required"'})    
  user = Users.query.filter_by(nme=auth.nme).first()  
  if check_password_hash(user.pwd, auth.pwd):  
     token = jwt.encode({'pid': user.pid, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SKEY'])  
     return jsonify({'token' : token.decode('UTF-8')}) 
  return make_response('could not verify',  401, { "login required"'})



@app.route('/api/user', methods=[ 'GET'])
@token_required 
def api_all():
    try:
        users =Users.query.all()
        all_user = []
        for user in users:
            data  = {}
            data['nme'] = user.nme
            data['no'] = user.no
            data['eml'] = user.eml
            all_user.append(data)
        return jsonify(all_user)
    except:
        return "<h1>unexpected error</h1>"
app.run()