# Part of CloudERPs/Ghaima fork. See LICENSE file for full copyright and licensing details.
"""HMAC-signed magic-link admin impersonation route.

Replaces what `bytekol_odoo_saas_bridge` used to provide for the SaaS
admin's "Login as user" feature. The flow is:

1. SaaS admin clicks "Login" on an `odoo.entity` record in the
   management UI, picks a user.
2. The management server (DBCLOUD) signs a token with the per-tenant
   secret stored in `entity.access_token` (DBCLOUD side) AND in the
   tenant's `ir.config_parameter` `ghaima.super_login_secret` (this
   side). Token format:
       base64url("<login>.<expires_unix>.<hmac_sha256_hex>")
3. The admin's browser is redirected to
       https://<tenant_fqdn>/super_user_login?token=<token>&login=<login>
4. This controller verifies the HMAC, checks expiry, finds the user,
   sets `request.session.uid` and redirects to `/odoo`.

Security:
- HMAC-SHA256 over `<login>.<expires>` with the per-tenant secret.
- 60-second expiry from the admin side.
- Constant-time HMAC comparison.
- Login mismatch between URL parameter and signed payload is rejected.
- Public route (auth='public'), but the signature can only be produced
  by someone holding the secret (= the SaaS admin server).
- TLS-only in practice (nginx terminates).
"""

import base64
import hashlib
import hmac
import logging
import time
from werkzeug.exceptions import Unauthorized

from odoo import http
from odoo.http import request


_logger = logging.getLogger(__name__)
_PARAM_KEY = 'ghaima.super_login_secret'


class GhaimaSuperLogin(http.Controller):

    @http.route(
        ['/super_user_login', '/saas_bridge_user_login'],
        type='http', auth='public', methods=['GET'],
        csrf=False, sitemap=False,
    )
    def super_user_login(self, token=None, login=None, redirect=None, debug=None, **kw):
        if not token or not login:
            _logger.warning("super_user_login: missing token/login (host=%s)",
                            request.httprequest.headers.get('Host'))
            raise Unauthorized("missing token or login")

        secret = request.env['ir.config_parameter'].sudo().get_param(_PARAM_KEY, default='')
        if not secret:
            _logger.warning("super_user_login: %s not set on this database", _PARAM_KEY)
            raise Unauthorized("super_user_login not configured for this entity")

        # Decode and parse token. Payload is "<login>.<expires>.<hmac>"; the
        # login itself can contain dots (email addresses), so split from the
        # right and take only the last 2 separators as field boundaries.
        try:
            padded = token + '=' * (-len(token) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8')
            tok_login, tok_expires_str, tok_hmac = decoded.rsplit('.', 2)
            tok_expires = int(tok_expires_str)
        except Exception:
            _logger.warning("super_user_login: malformed token")
            raise Unauthorized("malformed token")

        if tok_login != login:
            _logger.warning("super_user_login: login mismatch (url=%s, token=%s)", login, tok_login)
            raise Unauthorized("login mismatch")

        if tok_expires < int(time.time()):
            _logger.info("super_user_login: token expired for login=%s", login)
            raise Unauthorized("token expired")

        # Recompute and compare HMAC in constant time
        msg = f"{tok_login}.{tok_expires_str}".encode('utf-8')
        expected_hmac = hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_hmac, tok_hmac):
            _logger.warning("super_user_login: HMAC mismatch for login=%s", login)
            raise Unauthorized("invalid signature")

        # Resolve the user
        user = request.env['res.users'].sudo().search(
            [('login', '=', login), ('active', '=', True)], limit=1
        )
        if not user:
            _logger.warning("super_user_login: user %s not found / inactive", login)
            raise Unauthorized("user not found")

        # Establish the session as this user without password.
        request.session.uid = user.id
        request.session.login = user.login
        request.session.session_token = user._compute_session_token(request.session.sid)
        # Touch / regenerate session metadata so Odoo treats it as just authenticated
        request.update_env(user=user.id)

        _logger.info("super_user_login: authenticated as %s (uid=%s) on db=%s",
                     login, user.id, request.db)

        # Default landing on Odoo 18 web client
        target = redirect if redirect and redirect.startswith('/') else '/odoo'
        if debug:
            sep = '&' if '?' in target else '?'
            target = f"{target}{sep}debug={debug}"
        return request.redirect(target)
