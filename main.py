#!/usr/bin/env python

import webapp2
import re
import jinja2
import os
import hashlib
import hmac
import random
import string
import datetime
import json
import logging


from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.api import mail


# Global functions

jinja_environment = jinja2.Environment(
    autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')),
    extensions=['jinja2.ext.autoescape']
    )

def handle_404(request, response, exception):
    logging.exception(exception)
    response.write("No. Sorry, that's not a page I know. Go <a href='/'>Home</a>.")
    response.set_status(404)

def handle_500(request, response, exception):
    logging.exception(exception)
    response.write("A server error occurred! Go <a href='/'>Home</a>.")
    response.set_status(500)


def make_salt():
    r = random.SystemRandom()
    return ''.join(r.sample(string.letters + string.digits, 5))

def make_hash(name, pw, salt=''):
    if not salt:
        salt = make_salt()
    h = hmac.new(salt, name + pw, digestmod=hashlib.sha256).hexdigest()
    return ('%s|%s' % (h, salt))

def valid_hash(name, pw, h):
    salt = h.split('|')[1]
    test = make_hash(name, pw, salt)
    return test == h

def logged_in(self):
    user_cookie = str(self.request.cookies.get('user_id'))
    if user_cookie == 'None':
        return None
    name = user_cookie[0:user_cookie.find('|')]
    returned_hash = user_cookie[user_cookie.find('|')+1:]
    password = memcache.get(name + '_loginhash')
    if password == returned_hash:
    	return name

def make_session(self, name, password):
    session_hash = make_hash(name,password)
    self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/' % (name, session_hash))
    memcache.set(name + '_loginhash', session_hash)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")

def valid_pass(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

def valid_email(email):
    return not email or EMAIL_RE.match(email)

def blog_content(update = False):
    contents = memcache.get('blog')
    if contents is None or update:
        contents = list(db.GqlQuery("select * from Content order by created desc"))
        memcache.set('blog', contents)
    return contents


# databases

class Content(db.Model):

    username = db.StringProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class Users(db.Model):

    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)


# Modules

class BaseHandler(webapp2.RequestHandler):

    def handle_exception(self, exception, debug):
        # Log the error.
        logging.exception(exception)

        # Set a custom message.
        # self.response.out.write('')

        # If the exception is a HTTPException, use its error code.
        # Otherwise use a generic 500 error code.
        if isinstance(exception, webapp2.HTTPException):
            self.response.set_status(exception.code)
        else:
            self.response.set_status(500)

        self.response.out.write("An error ", exception.code, " occurred! Go <a href='/'>Home</a>.")


    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_environment.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))



class SignUp(BaseHandler):

    def write_form(self, name_error='', pass_error='',verify_error='', mail_error='', username='', email=''):
        template = jinja_environment.get_template('signup.html')

        self.response.out.write(template.render (
                                        bad_name = name_error,
                                        bad_pass = pass_error,
                                        bad_verify = verify_error,
                                        bad_mail = mail_error,
                                        username = username,
                                        email = email
                                        ))

    def get(self):
        self.write_form()

    def post(self):
        E_username = str(self.request.get('username'))
        E_password = self.request.get('password')
        E_verify = self.request.get('verify')
        E_email = self.request.get('email')

        username = valid_username(E_username)
        if not username:
            name_error = "That's not a valid username,"
        else:
            name_error = ''

        password = valid_pass(E_password)
        if not password:
            pass_error = "That wasn't a valid password."
        else:
            pass_error = ''

        valid = E_verify == E_password
        if not valid:
            verify_error = "Your passwords didn't match."
        else:
            verify_error = ''

        mail_error = ''

        if E_email:
            if not valid_email(E_email):
                mail_error = "That's not a valid email."
        else:
            E_email = ''

        if not (username and password and valid and mail_error == ''):
            self.write_form(name_error, pass_error, verify_error, mail_error, E_username, E_email)
        else:
            entry = db.GqlQuery("select * from Users where username=:1 limit 1", E_username).get()
            if entry: # user already in database, check password matches
                stored_hash = str(entry.password)
                if valid_hash(E_username, E_password, stored_hash):
                    make_session(self, E_username, E_password)
                    name = logged_in(self)
                    if name and '*' in name: # delete guest user if current
                        c = db.GqlQuery("select * from Users where username=:1", name).get()
                        c.delete()
                        memcache.delete(name + '_loginhash')
                    self.redirect("/welcome")
            if not entry: # new user
                hashed_pw = make_hash(E_username, E_password)
                a = Users(username=E_username, password=hashed_pw, email=E_email)
                a.put()
                mail.send_mail('mccoyhome@gmail.com' ,'mccoyhome@btinternet.com',
                    'New user signed up',E_username + ' email - ' + E_email)
                make_session(self, E_username,E_password)
                name = logged_in(self)
                if name and '*' in name: # delete guest user if current
                    c = db.GqlQuery("select * from Users where username=:1", name).get()
                    c.delete()
                    memcache.delete(name + '_loginhash')
                self.redirect("/welcome")

            name_error = "That username is already used"
            self.write_form(name_error, pass_error, verify_error, mail_error, E_username, E_email)


class Login(BaseHandler):

    def write_form(self, name_error='', pass_error='', loginerror='',  username=''):
        template = jinja_environment.get_template('login.html')

        self.response.out.write(template.render (
                                        bad_name = name_error,
                                        bad_pass = pass_error,
                                        log_error = loginerror,
                                        username = username,
                                        ))

    def get(self):
        self.write_form()

    def post(self):
        E_username = str(self.request.get('username'))
        E_password = self.request.get('password')

        username = valid_username(E_username)
        if not username:
            name_error = "That's not a valid username,"
        else:
            name_error = ''

        password = valid_pass(E_password)
        if not password:
            pass_error = "That wasn't a valid password."
        else:
            pass_error = ''

        if not (username and password):
            self.write_form(name_error, pass_error, '',  E_username)
        else:
            entry = db.GqlQuery("select * from Users where username=:1 limit 1", E_username).get()
            if entry:
                name = logged_in(self)
                if name and '*' in name: # delete guest user if current
                    c = db.GqlQuery("select * from Users where username=:1", name).get()
                    c.delete()
                    memcache.delete(name + '_loginhash')
                stored_hash = str(entry.password)
                if valid_hash(E_username, E_password, stored_hash):
                    make_session(self, E_username, E_password)
                    self.redirect("/welcome")
                else:
                    self.write_form('', 'Incorrect password', '', E_username)
            else:
                self.write_form('', '', "Don't know you, %s. Have you signed up?" % E_username, E_username)


class Logout(BaseHandler):

	def get(self):
		exp = datetime.date.today() + datetime.timedelta(days = -1)
		name = logged_in(self)
		if name:
			memcache.delete(name + '_loginhash')
			self.response.headers.add_header('Set-Cookie', "user_id=; expires='%s';path=/" % exp.strftime("%a, %d-%b-%Y 23:59:59 GMT"))
		self.redirect("/")



class welcomeHandler(BaseHandler):

    def get(self):

        name = logged_in(self)
        if name:
            self.render("welcome.html", name = name)
        else:
            self.redirect("/blog/signup")


class Blog(BaseHandler):

    def get(self):

        name = logged_in(self)
        if name == None:
            self.redirect("/blog/login")

        self.render("blog.html", contents = blog_content())

    def post(self):
        self.redirect("/blog/newpost")


class NewPost(BaseHandler):

    def get(self):

        name = logged_in(self)
        if name == None:
            self.redirect("/blog/login")

        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        name = logged_in(self)

        if subject and content:
            c = Content(username = name, subject = subject, content = content)
            c.put()
            contents = blog_content(True)
            ident = str(int(c.key().id()))
            memcache.set(ident, None)
            mail.send_mail('mccoyhome@gmail.com' ,'mccoyhome@btinternet.com',
                'New post - %s - by %s' % (subject, name),
                content)

            self.redirect("/blog/" + ident)
        else:
            error = "Need BOTH entries please"
            self.render("newpost.html", subject = subject, content = content, error = error)


class PagesHandler(BaseHandler):

    def get(self, ident):

        name = logged_in(self)
        if name == None or not ident:
            self.redirect("/blog/login")

        try:
            entry = int(ident)
        
            if not Content.get_by_id(entry):
                self.redirect("/")
                return

            if memcache.get(ident) is None:
                memcache.set(ident+"sub", Content.get_by_id(entry).subject)
                memcache.set(ident+"con", Content.get_by_id(entry).content)
                memcache.set(ident, True)
            self.render("page.html", subject = memcache.get(ident+"sub"), content = memcache.get(ident+"con"), ident = ident)
        except:
            self.redirect("/")


    def post(self, ident):

        entry = int(ident)
        subject = self.request.get("subject")
        content = self.request.get("content")
        name = logged_in(self)
        c = Content.get_by_id(entry)

        if c.username != name:
            error = "%s, you can't edit an entry made by %s." % (name, c.username)
            self.render("page.html", subject = c.subject, content = c.content, error = error, ident = ident)
        else:

            if subject and content:
                c.subject = subject
                c.content = content
                c.put()
                contents = blog_content(True)
                ident = str(int(c.key().id()))
                memcache.set(ident, None)
                mail.send_mail('mccoyhome@gmail.com' ,'mccoyhome@btinternet.com',
                'Edit of post - %s - by %s' % (subject, name),
                content)


                self.redirect("/blog")
            else:
                error = "Need both entries please"
                self.render("page.html", subject = c.subject, content = c.content, error = error, ident = ident)


class delete_Post(BaseHandler):

    def get(self, ident):

        name = logged_in(self)
        if name == None:
            self.redirect("/blog/login")

        entry = int(ident)

        if not Content.get_by_id(entry):
            self.handle_exception(404, True)
            return

        c = Content.get_by_id(entry)

        if c.username != name:
            error = "%s, you can't delete an entry made by %s." % (name, c.username)
            self.render("errorpage.html", subject = c.subject, content = c.content, error = error, ident = ident)
        else:
            self.render("confirm.html", name = name, subject = c.subject)

    def post(self, ident):

        entry = int(ident)
        password = self.request.get("password")
        name = logged_in(self)
        c = Content.get_by_id(entry)

        if not password:
            self.render("confirm.html", name = name, subject = c.subject, error = "Bad password")
        else:
            entry = db.GqlQuery("select * from Users where username=:1 limit 1", name).get()
            if entry:
                stored_hash = str(entry.password)
                if valid_hash(name, password, stored_hash):
                    c.delete()
                    ident = str(int(c.key().id()))
                    memcache.set(ident, None)
                    contents = blog_content(True)
                    self.redirect("/blog")
                else:
                    self.render("confirm.html", name = name, subject = c.subject, error = "Bad password")


class BlogJson(BaseHandler):

    def get(self):

        name = logged_in(self)
        if name == None:
            self.redirect("/blog/login")

        contents = blog_content()
        result = []

        for entry in contents:
            dic = {}
            dic["User"] = entry.username
            dic["subject"] = entry.subject
            dic["created"] = entry.created.strftime("%a %b %d %H:%M:%S %Y")
            dic["last_modified"] = entry.last_modified.strftime("%a %b %d %H:%M:%S %Y")
            dic["content"] = entry.content
            result.append(dic)

        self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
        self.response.out.write(json.dumps(result, indent = 4))


class PageJson(BaseHandler):

    def get(self, ident):

        name = logged_in(self)
        if name == None:
            self.redirect("/blog/login")

        entry = int(ident)

        if not Content.get_by_id(entry):
            self.handle_exception(404, True)
            return

        dic = {}
        dic["User"] = Content.get_by_id(entry).username
        dic["subject"] = Content.get_by_id(entry).subject
        dic["created"] = Content.get_by_id(entry).created.strftime("%a %b %d %H:%M:%S %Y")
        dic["last_modified"] = Content.get_by_id(entry).last_modified.strftime("%a %b %d %H:%M:%S %Y")
        dic["content"] = Content.get_by_id(entry).content

        self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
        self.response.out.write(json.dumps(dic, indent = 4))


class MainPage(BaseHandler):

    def get(self):
      
        name = logged_in(self)
        if name and '*' in name:
            name = 'Guest!'
        if name == None:
            name = 'Visitor'
        self.render('index.html', name = name)

    def post(self):

        password = make_salt()
        letters = make_salt()
        name = 'Guest*'+letters
        hashed_pw = make_hash(name, password)
        a = Users(username=name, password=hashed_pw, email='')
        a.put()
        make_session(self, name, password)
        self.render('index.html', name = 'Guest!')





app = webapp2.WSGIApplication([('/', MainPage),
                                ('/blog/signup', SignUp),
                                ('/blog/login', Login),
                                ('/blog/logout', Logout),
                                ('/welcome', welcomeHandler),
                                ('/blog', Blog),
                                ('/blog/.json', BlogJson),
                                ('/blog.json', BlogJson),
                                ('/blog/newpost', NewPost),
                                ('/blog/postdel/([0-9]+)?', delete_Post),
                                ('/blog/([0-9]+)?', PagesHandler),
                                ('/blog/([0-9]+)?/.json', PageJson),
                                ('/blog/([0-9]+)?.json', PageJson)
                                ],
                              debug=True)

app.error_handlers[404] = handle_404
app.error_handlers[500] = handle_500