from flask import request, jsonify

def interceptor_before_request():
    """Acts before every request (like an interceptor)"""
    print("==== BEFORE REQUEST INTERCEPTOR ====")
    print("Method:", request.method)
    print("Path:", request.path)

    
    if request.headers.get("X-Blocked") == "true":
        return jsonify({"error": "Request blocked by interceptor"}), 403