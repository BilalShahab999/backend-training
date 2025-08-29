from flask import request, jsonify

def log_request():
    print("==== MIDDLEWARE BEFORE REQUEST ====")
    print("Method:", request.method)
    print("Path:", request.path)
    print("Headers:", dict(request.headers))
    print("===================================")
