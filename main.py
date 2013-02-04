# import logging

import os
import json
import time

import webapp2
import jinja2

from utils import *

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


#
# DB MODELS
#

def users_key(group='default'):
    return db.Key.from_path('Users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).ancestor(users_key()).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and check_pw_hash(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):
    return db.Key.from_path('Blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d


#
# HANDLERS
#

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_cookie_hash(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_cookie_hash(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def cachefront(update=False):
    key = 'front'
    posts_cachetime = memcache.get(key)
    if posts_cachetime is None or update:
        posts = Post.all().ancestor(blog_key()).order('-created')
        posts_cachetime = (posts, time.time())
        memcache.set(key, posts_cachetime)
    return posts_cachetime


class BlogFront(BlogHandler):
    def get(self):
        posts, cachetime = cachefront()
        cachetime = round(time.time() - cachetime, 2)

        if self.request.url.endswith('.json'):
            self.render_json([p.as_dict() for p in posts])
        else:
            self.render('front.html', posts=posts, cachetime=cachetime)


def cachepost(post_id, update=False):
    key = 'permalink' + str(post_id)
    post_cachetime = memcache.get(key)
    if post_cachetime is None or update:
        dbkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(dbkey)
        post_cachetime = (post, time.time())
        memcache.set(key, post_cachetime)
    return post_cachetime


class PostPage(BlogHandler):
    def get(self, post_id):

        post, cachetime = cachepost(post_id)
        cachetime = round(time.time() - cachetime, 2)

        if not post:
            self.error(404)
            return

        if self.request.url.endswith('.json'):
            self.render_json(post.as_dict())
        else:
            self.render("permalink.html", post=post, cachetime=cachetime)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
            cachefront(True)
            cachepost(p.key().id(), True)
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            u = User.by_name(self.username)
            if u:
                params['error_username'] = 'That user already exists.'
                self.render('signup-form.html', **params)
            else:
                u = User.register(self.username, self.password, self.email)
                u.put()

                self.login(u)
                self.redirect('/')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


class MemcaheFlush(BlogHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')


app = webapp2.WSGIApplication([('/?(?:.json)?', BlogFront),
                               ('/([0-9]+)(?:.json)?', PostPage),
                               ('/newpost', NewPost),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/flush', MemcaheFlush)],
                              debug=True)
