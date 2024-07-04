#!/usr/bin/env python3
""" Module for hashing and validating passwords """
import bcrypt


def hash_password(password: str) -> bytes:
    """ xpects one string argument name password and returns a salted,
        hashed password, which is a byte string """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Expects 2 arguments and returns a boolean """
    return bcrypt.checkpw(password.encode(), hashed_password)
