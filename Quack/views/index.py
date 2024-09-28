"""Pages for Insta485."""
import os
import pathlib
import uuid
import hashlib
import flask
import arrow
from flask import render_template, request, session, url_for, abort, redirect
from werkzeug.utils import secure_filename
import Quack
from Quack import app

LOGGER = flask.logging.create_logger(Quack.app)


@Quack.app.route('/')
def show_index():
    """pine."""
    connection = Quack.model.get_db()
    connection.execute("PRAGMA foreign_keys = ON;")
    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))
    posts_query = """
        SELECT
            posts.postid,
            posts.filename,
            posts.owner,
            users.filename AS owner_img,
            posts.created
        FROM posts
        JOIN users ON posts.owner = users.username
        LEFT JOIN following
            ON following.username2 = posts.owner
            AND following.username1 = ?
        WHERE posts.owner = ? OR following.username1 = ?
        ORDER BY posts.postid DESC
    """
    posts = connection.execute(posts_query,
                               (logname, logname, logname)).fetchall()

    posts_data = []
    for post in posts:
        timestamp = arrow.get(post['created']).humanize()

        comments_query = """
            SELECT comments.owner, comments.text
            FROM comments
            WHERE comments.postid = ?
            ORDER BY comments.commentid ASC
        """
        comments = connection.execute(comments_query,
                                      (post['postid'],)).fetchall()

        likes_query = """
            SELECT COUNT(*) AS like_count
            FROM likes
            WHERE likes.postid = ?
        """
        like_count = connection.execute(
            likes_query, (post['postid'],)
        ).fetchone()['like_count']

        user_likes_query = """
            SELECT 1
            FROM likes
            WHERE postid = ? AND owner = ?
        """
        user_liked = connection.execute(user_likes_query,
                                        (post['postid'], logname)).fetchone()

        post_data = {
            "postid": post['postid'],
            "img_url": f"/uploads/{post['filename']}",
            "owner": post['owner'],
            "owner_img_url": f"/uploads/{post['owner_img']}",
            "timestamp": timestamp,
            "likes": like_count,
            "comments": comments,
            "liked_by_logname": user_liked is not None
        }
        posts_data.append(post_data)

    context = {"posts": posts_data, "logname": logname}
    return flask.render_template("index.html", **context)


@Quack.app.route('/uploads/<filename>')
def uploaded_file(filename):
    """File upload handling."""
    if 'logname' not in session:
        abort(403)
    upload_folder = pathlib.Path(Quack.app.config['UPLOAD_FOLDER'])
    file_path = upload_folder / filename
    if not file_path.exists():
        abort(404)
    return flask.send_from_directory(upload_folder, filename)


@Quack.app.route('/users/<user_url_slug>/')
def show_user(user_url_slug):
    """Display user's profile page."""
    connection = Quack.model.get_db()
    connection.execute("PRAGMA foreign_keys = ON;")

    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))
    user_query = """
        SELECT username, fullname
        FROM users
        WHERE username = ?
    """
    # checking if user exists
    user_info = connection.execute(user_query, (user_url_slug,)).fetchone()
    if user_info is None:
        abort(404)

    user_stats_query = """
        SELECT
            (SELECT COUNT(*)
            FROM posts
            WHERE owner = users.username) AS total_posts,
            (SELECT COUNT(*)
            FROM following
            WHERE username2 = users.username) AS followers,
            (SELECT COUNT(*)
            FROM following
            WHERE username1 = users.username) AS following
        FROM users
        WHERE username = ?
    """

    user_stats = connection.execute(user_stats_query,
                                    (user_url_slug,)).fetchone()

    follows_query = """
        SELECT 1
        FROM following
        WHERE username1 = ? AND username2 = ?
    """
    logname_follows_username = connection.execute(
        follows_query, (logname, user_url_slug)
    ).fetchone() is not None

    posts_query = """
        SELECT postid, filename
        FROM posts
        WHERE owner = ?
        ORDER BY postid DESC
    """
    posts = connection.execute(posts_query, (user_url_slug,)).fetchall()
    posts_data = [
        {
            "postid": post['postid'],
            "img_url": f"/uploads/{post['filename']}"
        }
        for post in posts
    ]
    context = {
        "username": user_info['username'],
        "fullname": user_info['fullname'],
        "total_posts": user_stats['total_posts'],
        "followers": user_stats['followers'],
        "following": user_stats['following'],
        "logname": logname,
        "logname_follows_username": logname_follows_username,
        "posts": posts_data
    }

    return flask.render_template("user.html", **context)


@Quack.app.route('/users/<user_url_slug>/followers/')
def show_followers(user_url_slug):
    """Display the followers of the user."""
    connection = Quack.model.get_db()
    connection.execute("PRAGMA foreign_keys = ON;")

    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))

    # Check if the user exists
    user_check_query = """
        SELECT 1
        FROM users
        WHERE username = ?
    """
    user_exists = connection.execute(user_check_query,
                                     (user_url_slug,)).fetchone()

    if not user_exists:
        abort(404)

    # Fetch followers of the user
    followers_query = """
        SELECT users.username, users.filename AS user_img,
            EXISTS (
                SELECT 1
                FROM following
                WHERE username1 = ? AND username2 = users.username
            ) AS logname_follows_username
        FROM following
        JOIN users ON following.username1 = users.username
        WHERE following.username2 = ?
    """
    followers = connection.execute(followers_query,
                                   (logname, user_url_slug)).fetchall()

    followers_data = []
    for follower in followers:
        follower_data = {
            "username": follower['username'],
            "user_img_url": f"/uploads/{follower['user_img']}",
            "logname_follows_username": (
                follower['logname_follows_username'] == 1
            )
        }
        followers_data.append(follower_data)

    current_page_url = request.path

    context = {
        "logname": logname,
        "followers": followers_data,
        "current_page_url": current_page_url
    }

    return render_template("followers.html", **context)


@Quack.app.route('/users/<user_url_slug>/following/')
def show_following(user_url_slug):
    """Display the list of users that the given user is following."""
    connection = Quack.model.get_db()
    connection.execute("PRAGMA foreign_keys = ON;")

    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))

    user_check_query = """
        SELECT 1
        FROM users
        WHERE username = ?
    """
    user_exists = connection.execute(user_check_query,
                                     (user_url_slug,)).fetchone()
    if not user_exists:
        abort(404)

    following_query = """
        SELECT users.username, users.filename AS user_img,
            EXISTS (
                SELECT 1
                FROM following
                WHERE username1 = ? AND username2 = users.username
            ) AS logname_follows_username
        FROM following
        JOIN users ON following.username2 = users.username
        WHERE following.username1 = ?
    """
    following = connection.execute(following_query,
                                   (logname, user_url_slug)).fetchall()

    following_data = []
    for user in following:
        user_data = {
            "username": user['username'],
            "user_img_url": f"/uploads/{user['user_img']}",
            "logname_follows_username": user['logname_follows_username'] == 1
        }
        following_data.append(user_data)

    current_page_url = request.path

    context = {
        "logname": logname,
        "following": following_data,
        "url_1": current_page_url
    }

    return render_template("following.html", **context)


def get_post(connection, postid_url_slug):
    """Fetch post details."""
    post_query = """
        SELECT
            posts.postid,
            posts.filename,
            posts.owner,
            users.filename AS owner_img,
            posts.created
        FROM posts
        JOIN users ON posts.owner = users.username
        WHERE posts.postid = ?
    """
    return connection.execute(post_query, (postid_url_slug,)).fetchone()


@Quack.app.route('/posts/<postid_url_slug>/')
def show_post(postid_url_slug):
    """Display a single post."""
    connection = Quack.model.get_db()
    connection.execute("PRAGMA foreign_keys = ON;")

    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))

    post = get_post(connection, postid_url_slug)

    if post is None:
        abort(404)

    comments_query = """
        SELECT comments.commentid, comments.owner, comments.text
        FROM comments
        WHERE comments.postid = ?
    """
    comments = connection.execute(comments_query, (post['postid'],)).fetchall()

    likes_query = """
        SELECT COUNT(*) AS like_count
        FROM likes
        WHERE likes.postid = ?
    """
    like_count = connection.execute(likes_query,
                                    (post['postid'],)).fetchone()['like_count']

    liked_by_logname_query = """
        SELECT 1
        FROM likes
        WHERE postid = ? AND owner = ?
    """
    liked_by_logname = connection.execute(liked_by_logname_query,
                                          (post['postid'], logname)).fetchone()

    comments_data = []
    for comment in comments:
        comment_data = {
            "owner": comment['owner'],
            "text": comment['text'],
            "commentid": comment['commentid'],
            "is_owner": comment['owner'] == logname
        }
        comments_data.append(comment_data)

    timestamp = arrow.get(post['created']).humanize()

    context = {
        "postid": post['postid'],
        "img_url": f"/uploads/{post['filename']}",
        "owner": post['owner'],
        "owner_img_url": f"/uploads/{post['owner_img']}",
        "likes": like_count,
        "comments": comments_data,
        "logname": logname,
        "liked_by_logname": liked_by_logname is not None,
        "is_owner": post['owner'] == logname,
        "timestamp": timestamp
    }

    return flask.render_template("post.html", **context)


@Quack.app.route('/explore/')
def explore_users():
    """Display the list of users the logged-in user is not following."""
    connection = Quack.model.get_db()
    connection.execute("PRAGMA foreign_keys = ON;")

    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))

    not_following_query = """
        SELECT users.username, users.filename AS user_img
        FROM users
        WHERE username != ?
        AND username NOT IN (
            SELECT username2
            FROM following
            WHERE username1 = ?
        )
    """
    not_following = connection.execute(not_following_query,
                                       (logname, logname)).fetchall()

    not_following_data = []
    for user in not_following:
        user_data = {
            "username": user['username'],
            "user_img_url": f"/uploads/{user['user_img']}",
        }
        not_following_data.append(user_data)

    context = {
        "logname": logname,
        "not_following": not_following_data,
    }

    return render_template("explore.html", **context)


@Quack.app.route('/accounts/login/')
def login():
    """Login."""
    if 'logname' in session:
        return redirect(url_for('show_index'))
    return render_template('login.html')


@Quack.app.route('/accounts/create/', methods=['GET'])
def create():
    """Adsfafd."""
    if 'logname' in session:
        return redirect(url_for('edit_account'))
    return render_template('create.html')


@Quack.app.route('/accounts/delete/', methods=['GET'])
def delete_account():
    """Display the account deletion confirmation page."""
    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))

    context = {
        "username": logname,
        "logname": logname
    }
    return render_template("delete.html", **context)


@Quack.app.route('/accounts/edit/', methods=['GET'])
def edit_account():
    """Display the account edit page."""
    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))

    connection = Quack.model.get_db()
    user_query = """
        SELECT username, fullname, email, filename
        FROM users
        WHERE username = ?
    """
    user = connection.execute(user_query, (logname,)).fetchone()

    if not user:
        return redirect(url_for('login'))

    context = {
        "username": user['username'],
        "fullname": user['fullname'],
        "email": user['email'],
        "profile_pic_url": f"/uploads/{user['filename']}",
        "logname": logname
    }
    return render_template("edit.html", **context)


@Quack.app.route('/accounts/password/', methods=['GET'])
def change_password():
    """Display the password change form."""
    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))
    context = {
        "username": logname,
        "logname": logname
    }
    return render_template("change_password.html", **context)


@Quack.app.route('/accounts/auth/', methods=['GET'])
def auth_check():
    """Return 200 if the user is logged in, 403 otherwise."""
    if 'logname' in session:
        return '', 200

    abort(403)


@Quack.app.route("/likes/", methods=["POST"])
def update_likes():
    """Handle the liking and unliking of posts."""
    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))

    postid = request.form["postid"]
    operation = request.form["operation"]
    target = request.args.get('target', '/')

    connection = Quack.model.get_db()
    connection.execute("PRAGMA foreign_keys = ON;")

    user_liked_query = """
        SELECT 1
        FROM likes
        WHERE postid = ? AND owner = ?
    """
    user_liked = connection.execute(user_liked_query,
                                    (postid, logname)).fetchone()

    if operation == "like":
        if user_liked:
            abort(409)
        connection.execute(
            "INSERT INTO likes (owner, postid) VALUES (?, ?)",
            (logname, postid)
        )
    elif operation == "unlike":
        if not user_liked:
            abort(409)
        connection.execute(
            "DELETE FROM likes WHERE owner = ? AND postid = ?",
            (logname, postid)
        )

    return redirect(target)


@Quack.app.route("/comments/", methods=["POST"])
def handle_comments():
    """Handle creating and deleting comments, then redirect."""
    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))

    operation = request.form.get("operation")
    postid = request.form.get("postid")
    commentid = request.form.get("commentid")
    text = request.form.get("text", "").strip()
    target = request.args.get("target", "/")

    connection = Quack.model.get_db()
    connection.execute("PRAGMA foreign_keys = ON;")

    if operation == "create":
        if not text:
            abort(400)
        connection.execute(
            "INSERT INTO comments (owner, postid, text) VALUES (?, ?, ?)",
            (logname, postid, text)
        )

    elif operation == "delete":
        if not commentid:
            abort(400)
        comment_query = """
            SELECT owner
            FROM comments
            WHERE commentid = ?
        """
        comment_owner = connection.execute(comment_query,
                                           (commentid,)).fetchone()

        if comment_owner is None or comment_owner["owner"] != logname:
            abort(403)

        connection.execute(
            "DELETE FROM comments WHERE commentid = ? AND owner = ?",
            (commentid, logname)
        )

    return redirect(target)


@Quack.app.route("/posts/", methods=["POST"])
def handle_posts():
    """Handle creating and deleting posts, then redirect."""
    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))

    operation = request.form.get("operation")
    postid = request.form.get("postid")
    target = request.args.get("target",
                              url_for('show_user', user_url_slug=logname))

    connection = Quack.model.get_db()
    connection.execute("PRAGMA foreign_keys = ON;")

    if operation == "create":

        if 'file' not in request.files or request.files['file'].filename == '':
            abort(400)

        fileobj = request.files['file']
        filename = fileobj.filename

        suffix = pathlib.Path(filename).suffix.lower()
        uuid_basename = f"{uuid.uuid4().hex}{suffix}"

        upload_folder = pathlib.Path(Quack.app.config['UPLOAD_FOLDER'])
        path = upload_folder / uuid_basename
        fileobj.save(path)

        connection.execute(
            "INSERT INTO posts (filename, owner) VALUES (?, ?)",
            (uuid_basename, logname)
        )

    elif operation == "delete":

        if not postid:
            abort(400)

        post_query = """
            SELECT filename, owner
            FROM posts
            WHERE postid = ?
        """
        post = connection.execute(post_query, (postid,)).fetchone()

        if post is None or post['owner'] != logname:
            abort(403)
        filename_to_delete = post['filename']
        upload_folder = pathlib.Path(Quack.app.config['UPLOAD_FOLDER'])
        file_path = upload_folder / filename_to_delete

        if file_path.exists():
            os.remove(file_path)

        connection.execute("DELETE FROM comments WHERE postid = ?", (postid,))
        connection.execute("DELETE FROM likes WHERE postid = ?", (postid,))
        connection.execute("DELETE FROM posts WHERE postid = ?", (postid,))

    return redirect(target)


@Quack.app.route("/following/", methods=["POST"])
def handle_following():
    """Handle follow and unfollow actions, then redirect."""
    logname = session.get('logname')
    if 'logname' not in session:
        return redirect(url_for('login'))

    operation = request.form.get("operation")
    username = request.form.get("username")
    target = request.args.get("target", "/")

    connection = Quack.model.get_db()
    connection.execute("PRAGMA foreign_keys = ON;")

    if operation == "follow":
        existing_following_query = """
            SELECT 1
            FROM following
            WHERE username1 = ? AND username2 = ?
        """
        already_following = connection.execute(existing_following_query,
                                               (logname, username)).fetchone()

        if already_following:
            abort(409)

        connection.execute(
            "INSERT INTO following (username1, username2) VALUES (?, ?)",
            (logname, username)
        )

    elif operation == "unfollow":
        existing_following_query = """
            SELECT 1
            FROM following
            WHERE username1 = ? AND username2 = ?
        """
        following = connection.execute(existing_following_query,
                                       (logname, username)).fetchone()

        if not following:
            abort(409)

        connection.execute(
            "DELETE FROM following WHERE username1 = ? AND username2 = ?",
            (logname, username)
        )

    return redirect(target)


@Quack.app.route("/accounts/logout/", methods=["POST"])
def logout():
    """Log out the user and redirect to the login page."""
    session.clear()
    return redirect(url_for('login'))


def hash_password(password, salt=None):
    """Hash the password with a salt."""
    algorithm = 'sha512'
    salt = salt or uuid.uuid4().hex
    password_salted = salt + password
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    return "$".join([algorithm, salt, password_hash])


def save_file(fileobj, upload_folder):
    """Save the uploaded file to the specified folder."""
    stem = uuid.uuid4().hex
    suffix = pathlib.Path(secure_filename(fileobj.filename)).suffix.lower()
    uuid_basename = f"{stem}{suffix}"
    path = upload_folder / uuid_basename
    fileobj.save(path)
    return uuid_basename


def handle_login(connection, target):
    """Handle user login operation."""
    username = request.form.get("username")
    password = request.form.get("password")
    if not (username and password):
        abort(400)

    user = connection.execute(
        "SELECT username, password FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user:
        abort(403)
    if hash_password(password,
                     user["password"].split("$")[1]) != user["password"]:
        abort(403)

    session.clear()
    session["logname"] = user["username"]
    return redirect(target)


def handle_create(connection, target):
    """Handle account creation operation."""
    username = request.form.get("username")
    password = request.form.get("password")
    fullname = request.form.get("fullname")
    email = request.form.get("email")
    fileobj = request.files.get("file")

    if not (username and password and fullname and email and fileobj):
        abort(400)

    existing_user = connection.execute(
        "SELECT username FROM users WHERE username = ?", (username,)
    ).fetchone()
    if existing_user:
        abort(409)

    password_db_string = hash_password(password)
    uuid_basename = save_file(fileobj,
                              pathlib.Path(app.config['UPLOAD_FOLDER']))

    connection.execute(
        "INSERT INTO users (username, password, fullname, email, filename) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, password_db_string, fullname, email, uuid_basename)
    )

    session.clear()
    session["logname"] = username
    return redirect(target)


def handle_delete(connection, logname, target):
    """Handle account deletion operation."""
    user_posts = connection.execute(
        "SELECT filename FROM posts WHERE owner = ?", (logname,)
    ).fetchall()
    upload_folder = pathlib.Path(app.config["UPLOAD_FOLDER"])
    for post in user_posts:
        post_path = upload_folder / post["filename"]
        if post_path.exists():
            os.remove(post_path)

    user_icon = connection.execute(
        "SELECT filename FROM users WHERE username = ?", (logname,)
    ).fetchone()["filename"]
    icon_path = upload_folder / user_icon
    if icon_path.exists():
        os.remove(icon_path)

    connection.execute("DELETE FROM users WHERE username = ?", (logname,))
    session.clear()
    return redirect(target)


def handle_edit_account(connection, logname, target):
    """Handle account editing operation."""
    fullname = request.form.get("fullname")
    email = request.form.get("email")
    fileobj = request.files.get("file")

    if not (fullname and email):
        abort(400)

    upload_folder = pathlib.Path(app.config["UPLOAD_FOLDER"])
    if fileobj:
        old_icon = connection.execute(
            "SELECT filename FROM users WHERE username = ?", (logname,)
        ).fetchone()["filename"]
        old_icon_path = upload_folder / old_icon
        if old_icon_path.exists():
            os.remove(old_icon_path)

        uuid_basename = save_file(fileobj, upload_folder)
        connection.execute(
            "UPDATE users SET fullname = ?, email = ?, filename = ? "
            "WHERE username = ?",
            (fullname, email, uuid_basename, logname)
        )
    else:
        connection.execute(
            "UPDATE users SET fullname = ?, email = ? WHERE username = ?",
            (fullname, email, logname)
        )

    return redirect(target)


def handle_update_password(connection, logname, target):
    """Handle password update operation."""
    old_password = request.form.get("password")
    new_password1 = request.form.get("new_password1")
    new_password2 = request.form.get("new_password2")

    if not (old_password and new_password1 and new_password2):
        abort(400)

    user = connection.execute(
        "SELECT password FROM users WHERE username = ?", (logname,)
    ).fetchone()

    if hash_password(old_password,
                     user["password"].split("$")[1]) != user["password"]:
        abort(403)

    if new_password1 != new_password2:
        abort(401)

    password_db_string = hash_password(new_password1)
    connection.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (password_db_string, logname)
    )

    return redirect(target)


@app.route("/accounts/", methods=["POST"])
def handle_account_operations():
    """Handle account operations."""
    operation = request.form.get("operation")
    target = request.args.get("target", "/")
    connection = Quack.model.get_db()
    logname = session.get("logname")

    if operation == "login":
        return handle_login(connection, target)
    if operation == "create":
        return handle_create(connection, target)
    if operation == "delete":
        if not logname:
            abort(403)
        return handle_delete(connection, logname, target)
    if operation == "edit_account":
        if not logname:
            abort(403)
        return handle_edit_account(connection, logname, target)
    if operation == "update_password":
        if not logname:
            abort(403)
        return handle_update_password(connection, logname, target)

    abort(400)
