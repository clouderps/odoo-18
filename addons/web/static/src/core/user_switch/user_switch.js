import { Component, onMounted, useRef, useState, useEffect } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { getLastConnectedUsers, setLastConnectedUsers } from "@web/core/user";
import { imageUrl } from "@web/core/utils/urls";

export class UserSwitch extends Component {
    static template = "web.login_user_switch";
    static props = {};

    setup() {
        const users = getLastConnectedUsers();
        this.root = useRef("root");
        this.state = useState({
            users,
            displayUserChoice: users.length > 1,
        });
        this.form = document.querySelector("form.oe_login_form");
        this.form.classList.toggle("d-none", users.length > 1);
        this.form.querySelector(":placeholder-shown")?.focus();
        useEffect(
            (el) => el?.querySelector("button.list-group-item-action")?.focus(),
            () => [this.root.el]
        );

        // CloudERPs/Ghaima opt-in: when the browser has no cached users,
        // ask the server for the entity's internal users (gated by the
        // `web.show_user_list_on_login` system parameter, default off).
        // Stock Odoo behavior is unchanged when the param is off — the
        // endpoint returns []. See addons/web/controllers/ghaima_login_users.py.
        onMounted(() => {
            if (this.state.users.length > 0) {
                return;
            }
            fetch("/web/login/users", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ jsonrpc: "2.0", params: {} }),
            })
                .then((r) => r.json())
                .then((res) => {
                    const serverUsers = (res && res.result) || [];
                    if (!serverUsers.length) {
                        return;
                    }
                    this.state.users = serverUsers;
                    this.state.displayUserChoice = serverUsers.length >= 1;
                    this.form.classList.toggle("d-none", true);
                })
                .catch(() => { /* leave the form visible on any failure */ });
        });
    }

    toggleFormDisplay() {
        this.state.displayUserChoice = !this.state.displayUserChoice && this.state.users.length;
        this.form.classList.toggle("d-none", this.state.displayUserChoice);
        this.form.querySelector(":placeholder-shown")?.focus();
    }

    getAvatarUrl({ partnerId, partnerWriteDate: unique }) {
        return imageUrl("res.partner", partnerId, "avatar_128", { unique });
    }

    remove(deletedUser) {
        this.state.users = this.state.users.filter((user) => user !== deletedUser);
        setLastConnectedUsers(this.state.users);
        if (!this.state.users.length) {
            this.fillForm();
        }
    }

    fillForm(login = "") {
        this.form.querySelector("input#login").value = login;
        this.form.querySelector("input#password").value = "";
        this.toggleFormDisplay();
    }
}

registry.category("public_components").add("web.user_switch", UserSwitch);
