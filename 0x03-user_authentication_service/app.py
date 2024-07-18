#!/usr/bin/env python3
"""API Routes for Authentication Service"""
from auth import Auth
from flask import (Flask,
                   jsonify,
                   request,
                   abort,
                   redirect)

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def hello_world() -> str:
    """ Base route for authentication service API """
    mesage = {"message": "Bienvenue"}
    return jsonify(mesage)


@app.route('/users', methods=['POST'])
def register_user() -> str:
    """Registers a new user if it does not exist before"""
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError:
        abort(400)

    try:
        user = AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400

    mesage = {"email": email, "message": "user created"}
    return jsonify(mesage)


@app.route('/sessions', methods=['POST'])
def log_in() -> str:
    """ Logs in a user and returns session ID """
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError:
        abort(400)

    if not AUTH.valid_login(email, password):
        abort(401)

    sess_id = AUTH.create_session(email)

    mesage = {"email": email, "message": "logged in"}
    response = jsonify(mesage)

    response.set_cookie("sess_id", sess_id)

    return response


@app.route('/sessions', methods=['DELETE'])
def log_out() -> str:
    """Find the user with the requested session ID.
    If the user exists destroy the session and redirect the user to GET /.
    If the user does not exist, respond with a 403 HTTP status.
    """
    sess_id = request.cookies.get("sess_id", None)

    if sess_id is None:
        abort(403)

    user = AUTH.get_user_from_sess_id(sess_id)

    if user is None:
        abort(403)

    AUTH.destroy_session(user.id)

    return redirect('/')


@app.route('/profile', methods=['GET'])
def profile() -> str:
    """ If the user exist, respond with a 200 HTTP status and a JSON Payload
    Otherwise respond with a 403 HTTP status.
    """
    sess_id = request.cookies.get("sess_id", None)

    if sess_id is None:
        abort(403)

    user = AUTH.get_user_from_sess_id(sess_id)

    if user is None:
        abort(403)

    mesage = {"email": user.email}

    return jsonify(mesage), 200


@app.route('/reset_password', methods=['POST'])
def reset_password() -> str:
    """If the email is not registered, respond with a 403 status code.
    Otherwise, generate a token and respond with a
    200 HTTP status and JSON Payload
    """
    try:
        email = request.form['email']
    except KeyError:
        abort(403)

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    mesage = {"email": email, "reset_token": reset_token}

    return jsonify(mesage), 200


@app.route('/reset_password', methods=['PUT'])
def update_password() -> str:
    """ PUT /reset_password
    Updates password with reset token
    Return:
        - 400 if bad request
        - 403 if not valid reset token
        - 200 and JSON Payload if valid
    """
    try:
        email = request.form['email']
        reset_token = request.form['reset_token']
        new_password = request.form['new_password']
    except KeyError:
        abort(400)

    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)

    mesage = {"email": email, "message": "Password updated"}
    return jsonify(mesage), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
