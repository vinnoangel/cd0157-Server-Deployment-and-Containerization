from flask import jsonify

def http_error_handler(error, message):
    return jsonify({
        "success": False,
        "error": error,
        "message": message
    }), error
    