from flask import render_template, request
from app.crypto import hash_password, encrypt_user_data
from app import app  # Import the app created in __init__.py

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = hash_password(password)
        encrypted = encrypt_user_data(username, password)
        return render_template("result.html", username=username, password=password,
                               hashed=hashed, encrypted=encrypted)
    return render_template("login.html")
