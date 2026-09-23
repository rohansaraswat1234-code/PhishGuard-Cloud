(() => {

    let csrfToken = null;
    let allUsers = [];

    const escapeHTML = value =>
        String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");


    function getAdminMain() {
        return document.querySelector(
            "[data-admin-content], .admin-main, .main-content, .dashboard-main, main"
        );
    }


    function showMessage(message, type) {

        const element =
            document.getElementById(
                "pgUsersMessage"
            );

        if (!element) return;

        element.textContent = message;
        element.className =
            "pg-users-message " + type;

        setTimeout(() => {
            element.className =
                "pg-users-message";
        }, 4000);
    }


    function renderUsers(users) {

        const tbody =
            document.getElementById(
                "pgUsersBody"
            );

        if (!tbody) return;

        if (!users.length) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5">
                        No users found.
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML =
            users.map(user => {

                const admin =
                    user.role === "admin";

                const status =
                    user.is_active
                    ? `<span class="pg-badge pg-active">Active</span>`
                    : `<span class="pg-badge pg-blocked">Blocked</span>`;

                let actions;

                if (admin) {

                    actions = `
                        <span class="pg-protected">
                            🔒 Protected
                        </span>
                    `;

                } else {

                    actions = `
                        <div class="pg-user-actions">

                            <button
                                class="pg-action-btn pg-block-btn"
                                data-action="block"
                                data-user-id="${user.id}"
                                data-user-name="${escapeHTML(user.name)}"
                                ${user.is_active ? "" : "disabled"}
                            >
                                🚫 Block
                            </button>

                            <button
                                class="pg-action-btn pg-unblock-btn"
                                data-action="unblock"
                                data-user-id="${user.id}"
                                data-user-name="${escapeHTML(user.name)}"
                                ${user.is_active ? "disabled" : ""}
                            >
                                ✓ Unblock
                            </button>

                            <button
                                class="pg-action-btn pg-delete-btn"
                                data-action="delete"
                                data-user-id="${user.id}"
                                data-user-name="${escapeHTML(user.name)}"
                            >
                                🗑 Delete
                            </button>

                        </div>
                    `;
                }

                return `
                    <tr
                        data-search="${escapeHTML(
                            (
                                user.name +
                                " " +
                                user.email
                            ).toLowerCase()
                        )}"
                    >

                        <td>
                            <div class="pg-user-name">
                                ${escapeHTML(user.name)}
                            </div>

                            <div class="pg-user-email">
                                ${escapeHTML(user.email)}
                            </div>
                        </td>

                        <td>
                            ${
                                admin
                                ? `<span class="pg-badge pg-admin">Admin</span>`
                                : "User"
                            }
                        </td>

                        <td>${status}</td>

                        <td>
                            ${escapeHTML(
                                user.created_at || "—"
                            )}
                        </td>

                        <td>${actions}</td>

                    </tr>
                `;

            }).join("");
    }


    async function loadUsers() {

        try {

            const response =
                await fetch(
                    "/admin/api/users-v2",
                    {
                        credentials:
                            "same-origin"
                    }
                );

            const data =
                await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    "Unable to load users"
                );
            }

            csrfToken =
                data.csrf_token || null;

            allUsers =
                data.users || [];

            renderUsers(allUsers);

        } catch (error) {

            showMessage(
                error.message,
                "error"
            );
        }
    }


    async function performAction(
        action,
        userId,
        name
    ) {

        let confirmation;

        if (action === "delete") {
            confirmation =
                `Permanently delete "${name}"?\n\n` +
                `User account and related data will be removed.`;
        }

        else if (action === "block") {
            confirmation =
                `Block "${name}"?\n\n` +
                `This user will not be able to use the User Portal.`;
        }

        else if (action === "unblock") {
            confirmation =
                `Unblock "${name}"?\n\n` +
                `This user will regain access to the User Portal.`;
        }

        else {
            return;
        }

        if (!confirm(confirmation)) {
            return;
        }

        let endpoint;

        if (action === "delete") {
            endpoint =
                `/admin/api/users-v2/${userId}/delete`;
        }

        else if (action === "block") {
            endpoint =
                `/admin/api/users-v3/${userId}/block`;
        }

        else {
            endpoint =
                `/admin/api/users-v3/${userId}/unblock`;
        }

        try {

            const headers = {};

            if (csrfToken) {
                headers["X-CSRF-Token"] =
                    csrfToken;
            }

            const response =
                await fetch(
                    endpoint,
                    {
                        method: "POST",
                        credentials: "same-origin",
                        headers
                    }
                );

            const data =
                await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    "Action failed"
                );
            }

            showMessage(
                data.message,
                "success"
            );

            await loadUsers();

        }

        catch (error) {

            console.error(
                "User management error:",
                error
            );

            showMessage(
                error.message,
                "error"
            );
        }
    }

    function createPanel() {

        if (
            document.getElementById(
                "pgUserManagement"
            )
        ) {
            return;
        }

        const main =
            getAdminMain();

        if (!main) return;

        const section =
            document.createElement(
                "section"
            );

        section.id =
            "pgUserManagement";

        section.className =
            "pg-users-panel admin-card";

        section.innerHTML = `
            <div class="pg-users-head">

                <div>
                    <h2>👥 User Management</h2>

                    <p>
                        Block, unblock or permanently
                        delete registered users.
                    </p>
                </div>

                <input
                    id="pgUserSearch"
                    class="pg-user-search"
                    placeholder="Search users..."
                >

            </div>

            <div
                id="pgUsersMessage"
                class="pg-users-message"
            ></div>

            <div class="pg-users-table-wrap">

                <table class="pg-users-table">

                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Joined</th>
                            <th>Actions</th>
                        </tr>
                    </thead>

                    <tbody id="pgUsersBody">
                        <tr>
                            <td colspan="5">
                                Loading users...
                            </td>
                        </tr>
                    </tbody>

                </table>

            </div>
        `;

        /*
         Direct Admin Overview me top par
         show hoga.
        */
        main.prepend(section);


        section.addEventListener(
            "click",
            event => {

                const button =
                    event.target.closest(
                        "[data-action]"
                    );

                if (!button) return;

                performAction(
                    button.dataset.action,
                    button.dataset.userId,
                    button.dataset.userName
                );
            }
        );


        const search =
            section.querySelector(
                "#pgUserSearch"
            );

        search.addEventListener(
            "input",
            () => {

                const query =
                    search.value
                        .trim()
                        .toLowerCase();

                const filtered =
                    allUsers.filter(
                        user =>
                            (
                                user.name +
                                " " +
                                user.email
                            )
                            .toLowerCase()
                            .includes(query)
                    );

                renderUsers(filtered);
            }
        );

        loadUsers();
    }


    function init() {

        if (
            window.location.pathname
                .replace(/\/+$/, "")
            !== "/admin"
        ) {
            return;
        }

        createPanel();
    }


    document.addEventListener(
        "DOMContentLoaded",
        init
    );

    /*
     Admin SPA navigation ke baad bhi
     section automatically wapas aa jayega.
    */
    setInterval(init, 700);

})();
