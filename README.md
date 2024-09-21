## Flask Secure App
This is template flask app that provides account login, registration, password reset, account activation and some paged views to list users, sessions and reported violations. It uses *TimedJSONWebSignatureSerializer* from 'itsdangerous' for time limited token generation. There is a separate model entity for holding session data in database. It allows to gather information about logged users, history of sessions and more importantly to forcibly invalidate all cookies in case any of them get "stolen".

To register new account there are three ways:
- forcibly insert proper query into database (example below)
- apply for new account with registration form and make user active directly in database
- fill mail server data in .env and use proper service to get activation link

## Setup
```
$ mkdir flask-app
$ cd flask-app
$ git clone {github-link} .
$ python3 -m venv venv
$ source venv/bin/activate
$ python3 app.py
```
## Save requirements
`pip freeze > requirements.txt`

## Install requirements
`pip install -r requirements.txt`

```
pragma table_info("report");
insert into report(explaination, user_reported_id, user_reporting_id) values('', 1, 1);

password: test
pragma table_info("user");
insert into user(username, email, password, active, blocked) values("test","test@gmail.com","$2b$12$nWAuOq9TH/0l6mdWPMB.Y.kboEuHMht5W4zuIupgblh3V3jL8OWiO",True,False);
insert into user(username, email, password, active, blocked) values("user","user@gmail.com","$2b$12$nWAuOq9TH/0l6mdWPMB.Y.kboEuHMht5W4zuIupgblh3V3jL8OWiO",True,False);
```

## Info
The app requires job for unblocking users when the expiration time for blockade is up

