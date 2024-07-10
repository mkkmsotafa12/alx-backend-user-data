#!/usr/bin/env python3
""" Class authentication to be used in this file """
from flask import request
from typing import List, TypeVar


class Auth:
    """ Authentication class """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Require auth
            Args:
                Path: path to file
                Excluded_paths: path not inlcuded
        """
        if not path or not excluded_paths:
            return True
        modified_list = list(map(lambda i: i.strip('/'), excluded_paths))
        modified_path = path.strip('/')
        if modified_path in modified_list:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Authentication header function """
        if not request:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers

    def current_user(self, request=None) -> TypeVar('User'):
        """ The current user function """
        return None
