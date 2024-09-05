## Flask Secure App
This app is template flask app that provides account login, registration, password reset, account activation. It uses 'TimedJSONWebSignatureSerializer' from 'itsdangerous' for time limited token generation.

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
>>> from app import db, User
>>> db.create_all()
>>> db.drop_all()
```
## Save requirements
`pip freeze > requirements.txt`

## Install requirements
`pip install -r requirements.txt`


## requires itsdangerous==2.0.1
https://stackoverflow.com/questions/74039971/importerror-cannot-import-name-timedjsonwebsignatureserializer-from-itsdange

