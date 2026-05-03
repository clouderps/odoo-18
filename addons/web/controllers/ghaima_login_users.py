# Part of CloudERPs/Ghaima fork. See LICENSE file for full copyright and licensing details.
"""Opt-in public endpoint that lists internal users for the current
database, used by the login page to populate the user-switcher when
the browser has no cached recent users.

Disabled by default (matches stock Odoo behavior). Enable per-tenant:
    ir.config_parameter web.show_user_list_on_login = True

Returns at most 20 internal users (login + name + partner image hash)
sorted by login. Portal/public users are filtered out.
"""

from odoo import http
from odoo.http import request
from odoo.tools import str2bool


_PARAM_KEY = 'web.show_user_list_on_login'
_MAX_USERS = 20


class GhaimaLoginUsers(http.Controller):

    @http.route('/web/login/users', type='json', auth='public', methods=['POST'], csrf=False)
    def list_login_users(self):
        """Return the internal users for the current DB if the tenant
        opted in via the `web.show_user_list_on_login` system parameter.
        Returns an empty list otherwise (default).
        """
        if not request.db:
            return []
        IrConfig = request.env['ir.config_parameter'].sudo()
        if not str2bool(IrConfig.get_param(_PARAM_KEY, default='False'), False):
            return []
        # base.group_user is the standard "Internal User" group.
        # We exclude system/portal/public — only real internal users get listed.
        try:
            internal_group = request.env.ref('base.group_user', raise_if_not_found=False).sudo()
            if not internal_group:
                return []
        except Exception:
            return []
        users = request.env['res.users'].sudo().search(
            [('groups_id', 'in', internal_group.id), ('active', '=', True), ('share', '=', False)],
            limit=_MAX_USERS,
            order='login asc',
        )
        return [
            {
                'login': u.login,
                'name': u.name,
                'partnerId': u.partner_id.id,
                'partnerWriteDate': u.partner_id.write_date and u.partner_id.write_date.isoformat() or False,
                'userId': u.id,
            }
            for u in users
        ]
