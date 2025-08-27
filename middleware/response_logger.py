def log_response(response):
    print("==== MIDDLEWARE AFTER RESPONSE ====")
    print("Status Code:", response.status)
    print("Headers:", dict(response.headers))
    print("===================================")
    return response