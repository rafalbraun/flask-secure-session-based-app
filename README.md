## Flask Secure App
This app is template flask app that provides account login, registration, password reset, account activation. It uses 'TimedJSONWebSignatureSerializer' from 'itsdangerous' for time limited token generation. There is a separate model entity for holding session data. It allows to gather information about logged users, history of sessions and more importantly to forcibly invalidate all cookies in case any of them get "stolen".

## Setup
```
$ mkdir flask-app
$ cd flask-app
$ python3 -m venv venv
$ source venv/bin/activate
$ python3 app.py
```

## Setup database
```
$ source venv/bin/activate
$ export FLASK_APP=app
$ flask shell
>>> from models import db, User, Session, Report
>>> db.create_all()
>>> db.drop_all()
```
## Save requirements
`pip freeze > requirements.txt`

## Install requirements
`pip install -r requirements.txt`


## requires itsdangerous==2.0.1
https://stackoverflow.com/questions/74039971/importerror-cannot-import-name-timedjsonwebsignatureserializer-from-itsdange

## permanent sessions
https://stackoverflow.com/questions/11783025/is-there-an-easy-way-to-make-sessions-timeout-in-flask




		<table>
			<tr>
				<th>user_id</th>
				<th>username</th>
				<th>created_at</th>
				<th>expires_at</th>
				<th>explaination</th>
				<th></th>
			</tr>
			{% for report in reports %}
			<tr>
				<td>{{ report.user_id }}</td>
				<td>{{ report.user_reported }}</td>
				<td>{{ report.created_at }}</td>
				<td>{{ report.expires_at }}</td>
				<td><p>{{ report.explaination }}</p></td>
				<td><a href="/block_user/{{ report.id }}">block</a></td>
			</tr>
			{% endfor %}
		</table>