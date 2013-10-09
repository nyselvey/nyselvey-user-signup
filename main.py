import os
import webapp2
import json
import re
import cgi
import random
import hashlib
import hmac
import jinja2

from datetime import datetime, timedelta
from string import letters
from google.appengine.api import memcache
from google.appengine.ext import db

################### Templating using jinja2 #########################
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'imsosecret'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

################### Cookies ###################
def make_secure_val(val):
  return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
  val = secure_val.split('|')[0]
  if secure_val == make_secure_val(val):
    return val

##################### BlogHandler  ############################ 
class BlogHandler(webapp2.RequestHandler):

# Templating
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
      params['user'] = self.user
      t = jinja_env.get_template(template)
      return t.render(params)

  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

  def render_json(self, d):
    json_txt = json.dumps(d)
    self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
    self.write(json_txt)

#Cookies
  def set_secure_cookie(self, name, val):
    cookie_val = make_secure_val(val)
    self.response.headers.add_header(
      'Set-Cookie',
      '%s=%s; Path=/' % (name, cookie_val))

  def read_secure_cookie(self, name):
    cookie_val = self.request.cookies.get(name)
    return cookie_val and check_secure_val(cookie_val)

  def login(self, user):
    self.set_secure_cookie('user-id', str(user.key().id()))

  def logout(self):
    self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

  def initialize(self, *a, **kw):
    webapp2.RequestHandler.initialize(self, *a, **kw)
    uid = self.read_secure_cookie('user-id')
    self.user = uid and User.by_id(int(uid))

    if self.request.url.endswith('.json'):
      self.format = 'json'
    else:
      self.format = 'html'

############################ MainPage ############################ 
class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

############################ Caching & Query #######################
def age_set(key, val):
  #looks up current time and stores it in a tuple
  save_time = datetime.utcnow()
  memcache.set(key, (val, save_time))

def age_get(key):
  #compute age in seconds and return
  r = memcache.get(key)
  if r:
    val, save_time = r
    age = (datetime.utcnow() - save_time).total_seconds()
  else:
    val, age = None, 0
  return val, age

def add_post(ip, post):
  #stores the blogpost in the database
  post.put()
  get_posts(update = True)
  return str(post.key().id())

def get_posts(update = False):
  #runs the database query
  q = Post.all().order('-created').fetch(limit = 10)
  mc_key = 'BLOGS'

  posts, age = age_get(mc_key)
  if update or posts is None:
    posts = list(q)
    age_set(mc_key, posts)
  return posts, age

def age_str(age):
  #takes an age and returns the string of that age
  s = 'This blog was queried %s seconds ago'
  age = int(age)
  if age == 1:
    s = s.replace('seconds', 'second')
  return s % age

############################ Hashing #######################
def make_salt(length = 5):
  #create a 5 letter length string
  return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
  #makes a pw hash
  if not salt:
    salt = make_salt()
  h = hashlib.sha256(name + pw + salt).hexdigest()
  return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
  #verifies the pw hash
  salt = h.split(',')[0]
  return h == make_pw_hash(name, password, salt)

############################ Blog Functions #######################
def users_key(group = 'default'):
  #creates an ancestor element to store users
  return db.Key.from_path('users', group)

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

def blog_key(name = 'default'):
  #returns blog's parent key
  return db.Key.from_path('blogs', name)

########################## User Object #########################
class User(db.Model):
  name = db.StringProperty(required = True)
  pw_hash = db.StringProperty(required = True)
  email = db.StringProperty()

  @classmethod
  def by_id(cls, uid):
    #loads the user from the database
    return User.get_by_id(uid, parent = users_key())

  @classmethod
  def by_name(cls, name):
    #looks up the user by its name
    u = User.all().filter('name =', name).get()
    return u

  @classmethod
  def register(cls, name, pw, email = None):
    #creates a new user, doesn't store in the database
    pw_hash = make_pw_hash(name, pw)
    return User(parent = users_key(),
                name = name,
                pw_hash = pw_hash,
                email = email)

  @classmethod
  def login(cls, name, pw):
    #refers to the user class, returns user if it exists
    u = cls.by_name(name)
    if u and valid_pw(name, pw, u.pw_hash):
      return u

##################### Post Object #######################
class Post(db.Model):
  #properties of a blog entry
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
      #replaces a new line with a line break
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def as_dict(self):
      #creates a dictionary representation of the post to render as json
      time_fmt = '%c'
      d = {'subject': self.subject,
           'content': self.content,
           'created': self.created.strftime(time_fmt),
           'last_modified': self.last_modified.strftime(time_fmt)}
      return d 

####################### BlogFront handler #################
class BlogFront(BlogHandler):
    def get(self):
        posts, age = get_posts(update=True)
        if self.format == 'html':
          self.render('front.html', posts = posts, age = age_str(age))
        else:
          return self.render_json([p.as_dict() for p in posts])

######## PostPage Handler #################
class PostPage(BlogHandler):
    def get(self, post_id):
        post_key = 'POST_' + post_id

        #check to see if the post is in teh cache
        #if not, look it up in the database
        post, age = age_get(post_key)
        if not post:
          key = db.Key.from_path('Post', int(post_id), 
                                  parent=blog_key())
          post = db.get(key)
          age_set(post_key, post) #set it to the cache
          age = 0

        if not post:
          self.error(404)
          return

        #if the format is html call render on "permalink.html"
        #otherwise call render_json
        if self.format == 'html':
          self.render("permalink.html", post = post, 
                      age = age_str(age))
        else:
          self.render_json(post.as_dict())

################# NewPost Handler blog/newpost #################
class NewPost(BlogHandler):
    def get(self):
      #perform get request on newpost.html
        self.render("newpost.html")

    def post(self):
      #get the parameters from the request
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, 
                      content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, 
                        content=content, error=error)

################# Registration Verification #################
#Regular expressions
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

#Validate user registration parameters
def valid_username(username):
  return username and USER_RE.match(username)

def valid_password(password):
  return password and PASSWORD_RE.match(password)

def valid_email(email):
  return not email or EMAIL_RE.match(email)

def escape_html(s):
  return cgi.escape(s, quote=True)

################# Signup Handler #################
class Signup(BlogHandler):
  def get(self):
    #perform get request on signup-form.html
    self.render("signup-form.html")

  def post(self):
    #if have_error = True, there is an error 
    have_error = False
    #sign up parameters from get request
    self.username = self.request.get('username')
    self.password = self.request.get('password')
    self.verify = self.request.get('verify')
    self.email = self.request.get('email')

    #validate the parameters, if a parameter is not valid, 
    #set have_error to True
    if not valid_username(self.username):
      error_username = "That is not a valid username."
      have_error = True

    if not valid_password(self.password):
      error_password = "That is not a valid password."
      have_error = True

    elif self.password != self.verify:
      error_verify = "Your passwords didn't match."
      have_error = True
          
    if not valid_email(self.email):
      error_email="That's not a valid email"
      have_error = True
    
    #if there is an error, render the signup form again with the error message  
    if have_error:
      self.render('signup-form.html', **params)
    else:
      self.done()

  def done(self, *a, **kw):
    raise NotImplementedError

################# Reigster Handler #################
class Register(Signup):
  def done(self):
    u = User.by_name(self.username)
    if u:
      msg = 'That user already exists.'
      self.render('signup-form.html', error_username = msg)
    else:
      u = User.register(self.username, self.password, self.email)
      u.put()

      #call login to set the cookie 
      self.login(u)
      self.redirect('/welcome')

################# Login Handler /blog/login #################
class Login(BlogHandler):
  def get(self):
    self.render('login-form.html')

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')

    u = User.login(username, password)
    if u:
      self.login(u)
      self.redirect('/blog')
    else:
      msg = 'Invalid login'
      self.render('login-form.html', error = msg)

################# Logout Handler /blog/logout #################
class Logout(BlogHandler):
  def get(self):
    #call logout
    self.logout()
    self.redirect('/signup')

################# Welcome Handler #################
class Welcome(BlogHandler):
  def get(self):
      if self.user:
        self.render('welcome.html', username = self.user.name)
      else:
        self.redirect('/signup')


app = webapp2.WSGIApplication([
    ('/', Welcome),
    ('/signup', Register),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout),
    ('/blog(?:\.json)?', BlogFront),
    ('/blog/([0-9]+)(?:\.json)?', PostPage),
    ('/blog/newpost', NewPost)
    ], debug=True)