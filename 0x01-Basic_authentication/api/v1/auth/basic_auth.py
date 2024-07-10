#!/usr/bin/env python3
""" BasicAuth to be used here """
from .auth import Auth
import re
import base64
from flask import jsonify
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """ BasicAuth class here"""
    def extract_base64_authorization_header(self, authorization_header: str) \
            -> str:
        """ Base64 extract pass """
        if not authorization_header:
            return None
        elif type(authorization_header) is not str:
            return None
        elif not authorization_header.startswith('Basic '):
            return None
        pattern = r'(?<=Basic ).+'
        match = re.findall(pattern, authorization_header)
        return match[0]

    def decode_base64_authorization_header(self,
                                           base64_d: str) -> str:
        """ Decode base at base64_d """
        if not base64_d:
            return None
        elif type(base64_d) is not str:
            return None
        try:
            decoded = base64.b64decode(base64_d)
            return decoded.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_d: str) -> (str, str):
        """ Exctract_user_credentials """
        if not decoded_base64_d:
            return (None, None)
        elif type(decoded_base64_d) is not str:
            return (None, None)
        elif ':' not in decoded_base64_d:
            return (None, None)
        return tuple(decoded_base64_d.split(':', maxsplit=1))

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """ User_object_from_credentials """
        if user_email is None or type(user_email) is not str:
            return None
        elif user_pwd is None or type(user_pwd) is not str:
            return None
        users = User.search({'email': user_email})
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Current user definition in current_user """
        if not request:
            return None
        auth = request.headers['Authorization']
        credentials = self.extract_base64_authorization_header(auth)
        if not credentials:
            return None
        decode = self.decode_base64_authorization_header(credentials)
        if not decode:
            return None
        decoded_credentials = self.extract_user_credentials(decode)
        if not decoded_credentials:
            return None
        user = self.user_object_from_credentials(decoded_credentials[0],
                                                 decoded_credentials[1])
        if not user:
            return None
        return jsonify(user.__dict__)
