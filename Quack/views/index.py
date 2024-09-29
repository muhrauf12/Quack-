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

app = Flask(__name__)

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

@Quack.app.route('/CodeQuaker/')
def get_code_quacker():
 #   connection = Quack.model.get_db()
    #connection.execute("PRAGMA foreign_keys = ON;")
  #  logname = session.get('logname')
  #  if 'logname' not in session:
  #      return redirect(url_for('get_login'))

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
    return render_template('Notesnew.html')

@Quack.app.route('/notes/')
def get_notes():
    return render_template('notes.html')

@Quack.app.route('/loginPage/')
def get_login():
    return render_template('loginPage.html')

@Quack.app.route('/Lessons/')
def get_lessons():
    return render_template('Lessons.html')

@Quack.app.route('/test/')
def testy():
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
        "parts": [{ "text": init_patient_info }]
      }
    }
    json_payload = json.dumps(payload)
    
    response = requests.post(url, headers=headers, data=json_payload)

    with open('out.txt', 'w') as f:

        response = requests.post(url, headers=headers, data=json_payload)
        response_stream_events = response.text.split('\n\n')

        seen_messages = set()

        useful_responses = []

        for event in response_stream_events:
            if event.startswith("data:"):
                event_data = event[5:]  
                try:
         
                    parsed_event = json.loads(event_data)
            
            
                    if parsed_event[0] == "output" and "outputs" in parsed_event[1]:
                        outputs = parsed_event[1]["outputs"]["output"]
                        for part in outputs:
                            if "parts" in part:
                                for text_item in part["parts"]:
                                    if "text" in text_item:
                                        text_content = text_item["text"]
                                        if text_content not in seen_messages:
                                            seen_messages.add(text_content)
                                            useful_responses.append(text_content)
                                    
                except json.JSONDecodeError:
                    print("Error parsing event:", event)

        for response in useful_responses:
            print(response)
        return render_template('test.html')
