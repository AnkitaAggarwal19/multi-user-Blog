import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'SECRET'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
    
    # check whether a user is currently logged in or not
    def logged_in(self, user):
        if not user:
            self.redirect('/login')
            return
        else:
	    return True

    # check if a that user owns that post or not
    def own_post(self, user, post):
        return int(post.user_id) == user.key().id()

    # check if the post exists or not
    def post_exists(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        return post

    # check whether the comment with the given comment id exists or not
    def comment_exists(self, commId):
        key = db.Key.from_path('Comment', int(commId))
        comment = db.get(key)

        if not comment:
            self.error(404)
            return
        return comment


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.StringProperty()
    likes = db.StringProperty(default = "0")
    dislikes = db.StringProperty(default = "0")

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Comment(db.Model):
    user_id = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    author = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
	return user.name

class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    def get(self):
        if self.logged_in(self.user):
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
	    p.user_id = str(self.user.key().id())
            p.put()
            postComment = Comment.all().filter('post_id =', p.key().id())
	    self.render("permalink.html", post=p, comments=postComment)
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class EditPost(BlogHandler):

    def get(self, postId):
        if self.logged_in(self.user):
            post = self.post_exists(postId)
            if post:
                if self.own_post(self.user, post):
                    self.render(
                        "editPost.html", subject=post.subject,
                        content=post.content)
                else:
                    postComment = Comment.all().filter('post_id =', postId)
                    self.render(
                        "permalink.html", post=post,
                        error="You can only edit your own posts.",
   			comments=postComment)

    def post(self, postId):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        post = self.post_exists(postId)
        if not post:
            return

        if not self.own_post(self.user, post):
            postComment = Comment.all().filter('post_id =', postId)
            self.render("permalink.html", post=post,
                        error="You can only edit your own post.",
                        comments=postComm)
        elif subject and content:
            post.subject = subject
            post.content = content
            post.put()
            postComment = Comment.all().filter('post_id =', postId)
            self.render("permalink.html", post=post, comments=postComment)
        else:
            error = "subject and content, please!"
            self.render(
	    "editpost.html", subject=subject, content=content, error=error)

class DeletePost(BlogHandler):

    def get(self, postId):
        if self.logged_in(self.user):
            post = self.post_exists(postId)
            if post:
                if self.own_post(self.user, post):
                    post.delete()
		    posts = "select * from Post order by created desc";
                    self.redirect('/blog/')
                else:
                    postComment = Comment.all().filter('post_id=', postId)
                    self.render(
                        "permalink.html", post=post,
                        error="You can only delete your own posts.",
                        comments=postComment)

class CommentPage(BlogHandler):

    def post(self, postId):
        if self.logged_in(self.user):
            newComment = self.request.get("comment")
            post = self.post_exists(postId)
            if not newComment:
                self.render(
                    "permalink.html", post=post,
                    content=newComment,
                    error="Not a valid comment")
                return

            # create a new comments row and update the Comment entity
            c = Comment(user_id=str(self.user.key().id()),
                        post_id=postId, comment=newComment,
                        author=self.user.name)
            c.put()

        
            if post:
                postComment = Comment.all().filter(
                'post_id =', postId).order('-created')
                self.render("permalink.html", post=post, comments=postComment)

class DelComment(BlogHandler):

    def get(self, commId):
        if not self.logged_in(self.user):
            return

        comment = self.comment_exists(commId)
        if not comment:
            return

        postId = comment.post_id
        post = self.post_exists(postId)
        if not post:
            return

        if int(comment.user_id) == self.user.key().id():
            comment.delete()
            postComment = Comment.all().filter(
                          'post_id =', postId).order('-created')
            self.render("permalink.html", post=post, comments=postComment)
        else:
            postComment = Comment.all().filter(
                          'post_id =', postId).order('-created')
            self.render(
                    "permalink.html",
                     post=post,
                     error="You can only delete the comments posted by you!",
                     comments=postComment)


class EditComment(BlogHandler):

    def get(self, commId):
        if not self.logged_in(self.user):
            return

        comment = self.comment_exists(commId)
        if not comment:
            return

        post = self.post_exists(comment.post_id)
        if not post:
            return
        postComment = Comment.all().filter(
            'post_id =', comment.post_id).order('-created')

        if int(comment.user_id) == self.user.key().id():
            self.render("editComment.html",
                         post=post,
                         content=comment.comment,
                         comment=comment)
        else:
            self.render("permalink.html",
                         post=post,
                         error="You can only edit the comments posted by you.!",
                         comments=postComment)

    def post(self, commId):
        if not self.logged_in(self.user):
            return

        comment = self.comment_exists(commId)
        if not comment:
            return

	post = self.post_exists(comment.post_id)
        if not post:
            return

        newComment = self.request.get("comment")
        if not newComment:
            error = "enter valid content"
            self.render("editComment.html", post=post, content=newComment, error=error, comment=comment)
            return

        # update the row and the Comment entity
        key = db.Key.from_path('Comment', int(commId))
        comment = db.get(key)
        comment.comment = newComment
        comment.put()

        postComment = Comment.all().filter(
            'post_id =', comment.post_id).order('-created')
        self.render("permalink.html", post=post, comments=postComment)

class PostComment(BlogHandler):

    def get(self, postId):
        if self.logged_in(self.user):
            post = self.post_exists(postId)
            if post:
                postComment = Comment.all().filter('post_id =', postId).order('-created')
                self.render("permalink.html", post=post, comments=postComment)

class LikeModel(db.Model):
    user_id = db.StringProperty()
    post_id = db.StringProperty()

    def get_UserName(self):
        user = User.by_id(self.user_id)
	return user.name

class LikePost(BlogHandler):

    def get(self, postId):
        if self.logged_in(self.user):
            post = self.post_exists(postId)
            if post:
                postComment = Comment.all().filter('post_id =', postId)
                if self.own_post(self.user, post):
                    self.render(
                        "permalink.html", post=post,
                        error="You cannot like your own post",
                        comments=postComment)
                    return

                likes = LikeModel.all()
                likes.filter('user_id =', str(self.user.key().id())).filter(
                    'post_id =', postId)

                if likes.get():
                    self.render(
                        "permalink.html", post=post,
                        error="This post is already liked by you.",
                        comments=postComment)
                    return

                lk = LikeModel(user_id=str(self.user.key().id()), post_id=postId)
                lk.put()

                post.likes = str(int(post.likes) + 1)
                post.put()
	        self.render("permalink.html", post=post, comments=postComment)

class DislikeModel(db.Model):
    user_id = db.StringProperty()
    post_id = db.StringProperty()

    def get_UserName(self):
        user = User.by_id(self.user_id)
	return user.name

class DislikePost(BlogHandler):

    def get(self, postId):
        if self.logged_in(self.user):
            post = self.post_exists(postId)
            if post:
                postComment = Comment.all().filter('post_id =', postId)
                if self.own_post(self.user, post):
                    return self.render(
                        "permalink.html",
                        post=post,
                        error="You cannot dislike your own post",
                        comments=postComment)

                dislikes = DislikeModel.all()
                dislikes.filter('user_id =', str(self.user.key().id())).filter(
                    'post_id =', postId)

                if dislikes.get():
                    self.render(
                        "permalink.html", post=post,
                        error="This post is already disliked by you.",
                        comments=postComment)
                    return

                dlk = DislikeModel(user_id=str(self.user.key().id()), post_id=postId)
                dlk.put()

                post.dislikes = str(int(post.dislikes) + 1)
                post.put()
		self.render("permalink.html", post=post, comments=postComment)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

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
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

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

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
			       ('/blog/delpost/([0-9]+)', DeletePost),
			       ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/commentPage/([0-9]+)', CommentPage),
		               ('/blog/delcomment/([0-9]+)', DelComment),
			       ('/blog/editcomment/([0-9]+)', EditComment),
			       ('/blog/comment/([0-9]+)', PostComment),
			       ('/blog/like/([0-9]+)', LikePost),
			       ('/blog/dislike/([0-9]+)', DislikePost)
                               ],
                              debug=True)
