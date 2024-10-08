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
from flask import Flask, request, render_template, jsonify
import requests
import json

index = Flask(__name__)

LOGGER = flask.logging.create_logger(Quack.app)

# API details
url = "https://breadboard-community.wl.r.appspot.com/boards/@AmusingHyena/quaky.bgl.api/run"

headers = {
    'Content-Type': 'application/json'
}

key = "bb-6g50294g4n3t44t6c374n2e615w246o4l3t632h33196w5i3m6"

@Quack.app.route('/')
def get_index():
    return render_template('index.html')

@Quack.app.route('/CodeQuacker/')
def get_code_quacker():
 #   connection = Quack.model.get_db()
    #connection.execute("PRAGMA foreign_keys = ON;")
  #  logname = session.get('logname')
  #  if 'logname' not in session:
  #      return redirect(url_for('get_login'))
    logged_in = "logname" in session
    return render_template('CodeQuacker.html')

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

@Quack.app.route('/Notesnew/')
def get_newNotes():
    logged_in = "logname" in session
    return render_template('Notesnew.html')

@Quack.app.route('/notes/')
def get_notes():
    logged_in = "logname" in session
    return render_template('notes.html')

@Quack.app.route('/createAccount/')
def get_accountC():
    return render_template('createAccount.html')

@Quack.app.route('/loginPage/')
def get_login():
    return render_template('loginPage.html')

@Quack.app.route('/Lessons/')
def get_lessons():
    logged_in = "logname" in session
    return render_template('Lessons.html')

@Quack.app.route('/test/')
def testy():
    logged_in = "logname" in session
    return render_template('test.html')

@app.route('/get_response', methods=['POST'])
def get_response():
    # Get the input from the form
    init_patient_info = request.form['input_text']

    # Prepare payload
    payload = {
        "$key": key,
        "text": {
            "role": "user",
            "parts": [{"text": init_patient_info}]
        }
    }
    json_payload = json.dumps(payload)
    
    response = requests.post(url, headers=headers, data=json_payload)

    # Open the output file
    with open('out.txt', 'w') as f:
        # Post request to the API and get the streamed events
        response = requests.post(url, headers=headers, data=json_payload)

        # Ensure response text is properly decoded to avoid weird characters
        response_text = response.content.decode('utf-8', errors='ignore')

        # Split response into individual events
        response_stream_events = response_text.split('\n\n')

        seen_messages = set()
        useful_responses = []

        # Define a flag to indicate when to start collecting responses
        start_collecting = False

        for event in response_stream_events:
            if event.startswith("data:"):
                event_data = event[5:].strip()
                try:
                    # Parse the JSON event data
                    parsed_event = json.loads(event_data)

                    # Check for the output type and extract text parts
                    if parsed_event[0] == "output" and "outputs" in parsed_event[1]:
                        outputs = parsed_event[1]["outputs"]["output"]

                        # Set the flag to true when we encounter the first valid output
                        if not start_collecting:
                            start_collecting = True

                        # Process only if we have started collecting useful content
                        if start_collecting:
                            for part in outputs:
                                if "parts" in part:
                                    for text_item in part["parts"]:
                                        if "text" in text_item:
                                            text_content = text_item["text"]

                                            # Skip if the response text is the same as the input
                                            if text_content.strip() == init_patient_info.strip():
                                                continue

                                            # Check for duplicate messages
                                            if text_content not in seen_messages:
                                                seen_messages.add(text_content)
                                                useful_responses.append(text_content)
                except json.JSONDecodeError:
                    print("Error parsing event:", event)

    # Combine useful responses into a single string
    final_response = " ".join(useful_responses)

    # Return the cleaned response text
    return final_response



@app.route("/logout/")
def handle_logout():
    session.clear()
    return redirect(url_for('get_login'))

@app.route("/create/", methods=["POST"])
def handle_create():
    connection = Quack.model.get_db()
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")

    if not (username and password and email):
        abort(400)

    existing_user = connection.execute(
        "SELECT username FROM users WHERE username = ?", (username,)
    ).fetchone()
    if existing_user:
        abort(409)

    password_db_string = (password)

    connection.execute(
        "INSERT INTO users (username, password, email) "
        "VALUES (?, ?, ?)",
        (username, password_db_string, email)
    )

    session.clear()
    session["logname"] = username
    return render_template('index.html')


@app.route("/accounts/", methods=["POST"])
def handle_login():
    """Handle user login operation."""
    #operation = request.form.get("operation")
    #target = request.args.get("target", "/")
    connection = Quack.model.get_db()
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

    session.clear()
    session["logname"] = user["username"]
    return render_template('index.html')