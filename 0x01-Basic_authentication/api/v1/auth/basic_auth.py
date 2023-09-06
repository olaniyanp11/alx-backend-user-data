#!/usr/bin/env python3
"""A basic authentication frame that inherits from Auth"""
from api.v1.auth.auth import Auth
from models.user import User
from typing import TypeVar, Tuple
import re
import binascii
import base64


class BasicAuth(Auth):
    """basic auth class"""

    def extract_base64_authorization_header(
        self,
            authorization_header: str) -> str:
        """ returns the Base64 part of the Authorization
            header for a Basic Authentication"""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        split_header = authorization_header.split(" ")
        if split_header[0] != "Basic":
            return None
        if not split_header[1]:
            return None
        return split_header[1]

    def decode_base64_authorization_header(
        self,
            base64_authorization_header: str) -> str:
        """returns the decoded value of a Base64
            string base64_authorization_header"""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            b64 = base64.b64decode(base64_authorization_header)
            return b64.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str,
            ) -> Tuple[str, str]:
        """Extracts user credentials from a base64-decoded authorization
        header that uses the Basic authentication flow.
        """
        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            field_match = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if field_match is not None:
                user = field_match.group('user')
                password = field_match.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
        self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """returns the User instance based on his email and password"""
        if user_email is None or user_pwd is None:
            return None
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None
        try:
            user = User.search({'email': user_email})
        except Exception:
            return None
        if len(user) <= 0 or user[0].is_valid_password(user_pwd):
            return None
        return user[0]

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the user from a request"""
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)

