#!/usr/bin/env python
"""
A simple app to create a JWT token.
"""
import os
import logging
import datetime
import functools
import jwt

# pylint: disable=import-error
from flask import Flask, jsonify, request, abort

from http_status_codes import *
from error_handler import http_error_handler


JWT_SECRET = os.environ.get('JWT_SECRET', 'abc123abc1234')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')


def _logger():
    '''
    Setup logger format, level, and handler.

    RETURNS: log object
    '''
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    log = logging.getLogger(__name__)
    log.setLevel(LOG_LEVEL)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    log.addHandler(stream_handler)
    return log


LOG = _logger()
LOG.debug("Starting with log level: %s" % LOG_LEVEL )
APP = Flask(__name__)

def require_jwt(function):
    """
    Decorator to check valid jwt is present.
    """
    @functools.wraps(function)
    def decorated_function(*args, **kws):
        if not 'Authorization' in request.headers:
            abort(401)
        data = request.headers['Authorization']
        token = str.replace(str(data), 'Bearer ', '')
        try:
            jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except: # pylint: disable=bare-except
            abort(401)

        return function(*args, **kws)
    return decorated_function


@APP.route('/', methods=['POST', 'GET'])
def health():
    return jsonify("Healthy")


@APP.route('/auth', methods=['POST'])
def auth():
    """
    Create JWT token based on email.
    """
    request_data = request.get_json()
    email = request_data.get('email')
    password = request_data.get('password')
    if not email:
        LOG.error("No email provided")
        return http_error_handler(error=HTTP_400_BAD_REQUEST, message="Missing parameter: email")
    if not password:
        LOG.error("No password provided")
        return http_error_handler(error=HTTP_400_BAD_REQUEST, message="Missing parameter: password")
    body = {'email': email, 'password': password}

    user_data = body

    return jsonify(token=_get_jwt(user_data).decode('utf-8'))


@APP.route('/contents', methods=['GET'])
def decode_jwt():
    """
    Check user token and return non-secret data
    """
    if not 'Authorization' in request.headers:
        return http_error_handler(error=HTTP_401_UNAUTHORIZED, message="Authorization header is expected.")
    data = request.headers['Authorization']
    token = str.replace(str(data), 'Bearer ', '')
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except: # pylint: disable=bare-except
        return http_error_handler(error=HTTP_401_UNAUTHORIZED, message="Invalid Token: Unauthorized user")


    response = {'email': data['email'],
                'exp': data['exp'],
                'nbf': data['nbf'] }
    return jsonify(**response)


def _get_jwt(user_data):
    exp_time = datetime.datetime.utcnow() + datetime.timedelta(weeks=2)
    payload = {'exp': exp_time,
               'nbf': datetime.datetime.utcnow(),
               'email': user_data['email']}
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


'''
    error handler should conform to general task above
'''

@APP.errorhandler(HTTP_400_BAD_REQUEST)
def bad_request(error):
    return http_error_handler(HTTP_400_BAD_REQUEST, "bad request")

@APP.errorhandler(HTTP_401_UNAUTHORIZED)
def unauthorized(error):
    return http_error_handler(HTTP_401_UNAUTHORIZED, "unauthorized")

@APP.errorhandler(HTTP_403_FORBIDDEN)
def forbidden(error):
    return http_error_handler(HTTP_403_FORBIDDEN, "forbidden")

@APP.errorhandler(HTTP_404_NOT_FOUND)
def not_found(error):
    return http_error_handler(HTTP_404_NOT_FOUND, "resource not found")
    
@APP.errorhandler(HTTP_405_METHOD_NOT_ALLOWED)
def method_not_allowed(error):
    return http_error_handler(HTTP_405_METHOD_NOT_ALLOWED, "method not allowed")
    
@APP.errorhandler(HTTP_408_REQUEST_TIMEOUT)
def request_timeout(error):
    return http_error_handler(HTTP_408_REQUEST_TIMEOUT, "request timeout")
    
@APP.errorhandler(HTTP_409_CONFLICT)
def conflict(error):
    return http_error_handler(HTTP_409_CONFLICT, "request conflicts")
    
@APP.errorhandler(HTTP_422_UNPROCESSABLE_ENTITY)
def unprocessable(error):
    return http_error_handler(HTTP_422_UNPROCESSABLE_ENTITY, "unprocessable")
    
@APP.errorhandler(HTTP_500_INTERNAL_SERVER_ERROR)
def internal_server_error(error):
    return http_error_handler(HTTP_500_INTERNAL_SERVER_ERROR, "internal server error")


if __name__ == '__main__':
    APP.run(host='127.0.0.1', port=8080, debug=True)
