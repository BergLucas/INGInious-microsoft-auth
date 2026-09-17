from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

import flask
from flask import Response, send_from_directory
from inginious.frontend.user_manager import AuthMethod
from requests_oauthlib import OAuth2Session
from inginious.frontend.pages.utils import INGIniousPage

if TYPE_CHECKING:
    from inginious.client.client import Client
    from inginious.frontend.plugins import PluginManager


AUTHORISATION_BASE_URL = (
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
)
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
SCOPE = [
    "openid",
    "profile",
]

PATH_TO_PLUGIN = os.path.abspath(os.path.dirname(__file__))


class MicrosoftAuthStatic(INGIniousPage):
    """Serve static files for the Microsoft authentication plugin."""

    def GET(self, path: str) -> Response:  # noqa: N802
        """Serve static files for the Microsoft authentication plugin.

        Args:
            path: The path to the static file.

        Returns:
            The static file.
        """
        return send_from_directory(os.path.join(PATH_TO_PLUGIN, "static"), path)


class MicrosoftAuthMethod(AuthMethod):
    """Microsoft authentication method."""

    def get_auth_link(self, auth_storage: dict[str, Any]) -> str:
        microsoft = OAuth2Session(
            self._client_id,
            scope=SCOPE,
            redirect_uri=flask.request.url_root + self._callback_page,
        )

        authorization_url, state = microsoft.authorization_url(AUTHORISATION_BASE_URL)

        auth_storage["oauth_state"] = state

        return authorization_url

    def callback(
        self, auth_storage: dict[str, Any]
    ) -> tuple[str, str, str, dict] | None:
        microsoft = OAuth2Session(
            self._client_id,
            state=auth_storage["oauth_state"],
            redirect_uri=flask.request.url_root + self._callback_page,
            scope=SCOPE,
        )

        try:
            microsoft.fetch_token(
                TOKEN_URL,
                client_secret=self._client_secret,
                authorization_response=flask.request.url,
            )

            response = microsoft.get("https://graph.microsoft.com/oidc/userinfo")

            profile = json.loads(response.content.decode("utf-8"))
        except Exception:
            return None

        if (email := profile.get("email")) is None:
            return None

        profile_id = str(profile["sub"])

        return profile_id, profile.get("name", profile_id), email, {}

    def __init__(
        self,
        id: str,
        name: str,
        client_id: str,
        client_secret: str,
    ):
        self._id = id
        self._name = name
        self._client_id = client_id
        self._client_secret = client_secret
        self._callback_page = "auth/callback/" + self._id

    def get_id(self) -> str:
        return self._id

    def get_name(self) -> str:
        return self._name

    def get_imlink(self) -> str:
        return '<img src="/plugins/microsoft-auth/static/icons/microsoft-icon.svg">'


def init(plugin_manager: PluginManager, client: Client, plugin_config: dict[str, Any]):
    if plugin_config.get("debug", False):
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    client_id = plugin_config.get("client_id", "")
    client_secret = plugin_config.get("client_secret", "")

    plugin_manager.add_page(
        "/plugins/microsoft-auth/static/<path:path>",
        MicrosoftAuthStatic.as_view("microsoft_auth_static"),
    )
    plugin_manager.register_auth_method(
        MicrosoftAuthMethod(
            plugin_config["id"],
            plugin_config.get("name", "Microsoft"),
            client_id,
            client_secret,
        )
    )
