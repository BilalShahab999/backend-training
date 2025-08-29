
def interceptor_after_request(response):
    """Acts after every request (like an interceptor)"""
    print("==== AFTER REQUEST INTERCEPTOR ====")
    print("Status:", response.status)

   
    response.headers["X-Interceptor"] = "Active"
    return response
