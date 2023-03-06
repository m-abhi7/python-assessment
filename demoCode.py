import os

from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_socketio import SocketIO, send, emit, join_room, leave_room

app = Flask(__name__)
app.config['SECRET_KEY'] = '446C9EEDEA5C1471D27E5F826D145'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.getcwd().replace("\\",'/') + '/users.db'

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins='*')

usersDict = {}

@socketio.on('message')
def handleMessage(msg):
	print('Message: ' + msg)
	send(msg, broadcast=True)
	
@socketio.on('username', namespace = '/private')
def receiveUsername(username):
	usersDict[username] = request.sid
	print(usersDict)
	
@socketio.on('privateMessage', namespace = '/private')
def privateMessage(payload):
	sessionID = usersDict[payload['toUser']]
	messageText = payload['messageText']
	fromUser = payload['fromUser']
	emit('newPrivateMessage', {"messageText":messageText, "toUser":payload['toUser'], "fromUser":fromUser}, room = sessionID)

@socketio.on('joinRoom')
def on_join(data):
	username = data['username']
	room = data['room']
	join_room(room)
	emit('joinedRoom', {'username': username, 'room': room}, room=room)

@socketio.on('leaveRoom')
def on_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    emit('left', {'username': username, 'room': room}, room=room)

@socketio.on('groupMessage')
def handle_message(data):
    username = data['username']
    room = data['room']
    message = data['messageText']
    emit('message', {'username': username, 'message': message}, room=room)

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Groups(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    groupName = db.Column(db.String(100), unique=True, nullable=False)

class UserGroupMapping(db.Model):
    userID = db.Column(db.Integer, db.ForeignKey(Users.id), primary_key=True)
    groupID = db.Column(db.Integer, db.ForeignKey(Groups.id), primary_key=True)

with app.app_context():
    db.create_all()    
    if not Users.query.first():
        admin = Users(username= "admin", password = "admin", is_admin = True)
        db.session.add(admin)
        user = Users(username= "user", password = "user", is_admin = False)
        db.session.add(user)
        db.session.commit()        

@app.route('/', methods=['GET', 'POST'])
def index():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		user = Users.query.filter_by(username=username).first()
		session['username'] = username
		if user and user.is_admin and user.password == password:
			session['isAdmin'] = True
			return redirect(url_for('admin', username=username))
		if user and not user.is_admin and user.password == password:
			session['isAdmin'] = False
			return redirect(url_for('user', username=username))
		flash('Error logging in. Please check username and password.')
		return redirect(url_for('index'))
		
	elif request.method == 'GET':
		return render_template('index.html')

@app.route('/admin')
def admin():
	username = session['username']
	users = Users.query.all()
	return render_template('adminPage.html', username = username, users=users)
	
@app.route('/user')
def user():
	username = session['username']
	users = Users.query.filter_by(is_admin=False).all()
	groups = Groups.query.all()
	return render_template('userPage.html', username = username, users=users, groups = groups)
	
@app.route('/chatWithUser/<int:user_id>', methods=['GET', 'POST'])
def chatWithUser(user_id):
	username = session['username']
	user = Users.query.filter_by(id=user_id).first()
	return render_template('chatPage.html', username = username, user=user)

@app.route('/chatWithGroup/<int:groupID>', methods=['GET', 'POST'])
def chatWithGroup(groupID):
	group = Groups.query.filter_by(id=groupID).first()
	username = session['username']
	print(group, username)
	return render_template('groupChat.html', username = username, group = group)

@app.route('/editGroup/<int:groupID>', methods=['GET', 'POST'])
def editGroup(groupID):
	group = Groups.query.filter_by(id=groupID).first()
	users = Users.query.filter_by(is_admin=False).all()
	tempUsers = UserGroupMapping.query.filter_by(groupID=groupID).all()
	tempUsers = [x.userID for x in tempUsers]
	inGroupUsers = Users.query.filter(Users.id.in_(tempUsers)).filter(Users.is_admin == False).all()
	notInGroupUsers = Users.query.filter(Users.id.not_in(tempUsers)).filter(Users.is_admin == False).all()
	return render_template('editGroup.html', username = session['username'], group = group, inGroupUsers=inGroupUsers, notInGroupUsers=notInGroupUsers)

@app.route('/addUserToGroup/<int:groupID>', methods=['GET', 'POST'])
def addUserToGroup(groupID):
	if request.method == 'POST':
		userID = request.form['addUserID']
		try:
			db.session.add(UserGroupMapping(userID=userID, groupID=groupID))
			db.session.commit()
		except:
			flash('Error adding user to group')
	return redirect(url_for('editGroup', groupID=groupID))
	
@app.route('/removeUserFromGroup/<int:groupID>', methods=['GET', 'POST'])
def removeUserFromGroup(groupID):
	if request.method == 'POST':
		userID = request.form['removeUserID']
		try:
			UserGroupMapping.query.filter_by(userID=userID, groupID=groupID).delete()
			db.session.commit()        
		except:
			flash('Error removing user from group')
	return redirect(url_for('editGroup', groupID=groupID))

@app.route('/create', methods=['GET', 'POST'])
def create():
	if request.method == 'POST':
		user = Users.query.filter_by(username=session['username']).first()
		if user and user.is_admin:
			newUsername = request.form['newUsername']
			newPassword = request.form['newUsername']
			isAdmin = True if request.form['isAdmin'] == "1" else False
			try:
				user = Users(username=newUsername, password=newPassword, is_admin=isAdmin)
				db.session.add(user)
				db.session.commit()
			except:
				flash('Error creating, please try again')
		return redirect(url_for('admin', username=session['username']))			
	return redirect(url_for('admin', username=session['username']))			

@app.route('/newGroup', methods=['GET', 'POST'])
def newGroup():
	if request.method == 'POST':
		newGroupName = request.form['newGroupName']
		#newGroupUser = request.form['addNewGroupUser']
		try:
			group = Groups(groupName=newGroupName)
			db.session.add(group)
			db.session.commit()
		except:
			flash('Error creating group, please try again')
	return redirect(url_for('user'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
	if request.method == 'POST':
		user = Users.query.filter_by(id=user_id).first()
		user.username = request.form['editUsername']
		user.password = request.form['editPassword']
		isAdmin = True if request.form['isAdmin'] == "1" else False
		user.is_admin = isAdmin
		db.session.commit()
		return redirect(url_for('admin', username=session['username']))
	username = session['username']
	user = Users.query.filter_by(id=user_id).first()
	return render_template('editPage.html', username=username, user=user)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

#app.run()
if __name__ == '__main__':
	socketio.run(app, debug=True)