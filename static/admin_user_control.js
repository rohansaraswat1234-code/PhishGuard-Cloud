(() => {

    let csrfToken = null;
    let users = [];

    const esc = value =>
        String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");


    function getMain() {
        return document.querySelector(
            "[data-admin-content], .admin-main, .main-content, .dashboard-main, main"
        );
    }


    function message(text, type = "success") {

        const box = document.getElementById("adminUserMessage");

        if (!box) return;

        box.textContent = text;
        box.className = "admin-user-message " + type;

        setTimeout(() => {
            box.className = "admin-user-message";
        }, 3500);
    }


    function render(list) {

        const body = document.getElementById("adminUsersBody");

        if (!body) return;

        if (!list.length) {
            body.innerHTML = `
                <tr>
                    <td colspan="5">No users found.</td>
                </tr>
            `;
            return;
        }

        body.innerHTML = list.map(user => {

            const isAdmin = user.role === "admin";

            let actions = `
                <span class="admin-protected">
                    🔒 Protected
                </span>
            `;

            if (!isAdmin) {

                actions = `
                    <div class="admin-user-actions">

                        <button
                            class="admin-action block"
                            data-action="block"
                            data-id="${user.id}"
                            data-name="${esc(user.name)}"
                            ${user.is_active ? "" : "disabled"}
                        >
                            🚫 Block
                        </button>

                        <button
                            class="admin-action unblock"
                            data-action="unblock"
                            data-id="${user.id}"
                            data-name="${esc(user.name)}"
                            ${user.is_active ? "disabled" : ""}
                        >
                            ✓ Unblock
                        </button>

                        <button
                            class="admin-action delete"
                            data-action="delete"
                            data-id="${user.id}"
                            data-name="${esc(user.name)}"
                        >
                            🗑 Delete
                        </button>

                    </div>
                `;
            }

            return `
                <tr>

                    <td>
                        <strong>${esc(user.name)}</strong>
                        <div class="admin-user-email">
                            ${esc(user.email)}
                        </div>
                    </td>

                    <td>
                        ${
                            isAdmin
                            ? '<span class="admin-role-badge">Admin</span>'
                            : "User"
                        }
                    </td>

                    <td>
                        ${
                            user.is_active
                            ? '<span class="admin-status active">Active</span>'
                            : '<span class="admin-status blocked">Blocked</span>'
                        }
                    </td>

                    <td>
                        ${esc(user.created_at || "—")}
                    </td>

                    <td>
                        ${actions}
                    </td>

                </tr>
            `;

        }).join("");
    }


    async function loadUsers() {

        try {

            const response = await fetch(
                "/admin/api/user-control",
                {
                    credentials: "same-origin"
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error || "Unable to load users"
                );
            }

            users = data.users || [];
            csrfToken = data.csrf_token || null;

            render(users);

        } catch (error) {

            console.error(error);
            message(error.message, "error");
        }
    }


    async function runAction(action, id, name) {

        let confirmText = "";

        if (action === "block") {
            confirmText =
                `Block "${name}"?\n\nUser portal access will be disabled.`;
        }

        if (action === "unblock") {
            confirmText =
                `Unblock "${name}"?\n\nUser portal access will be restored.`;
        }

        if (action === "delete") {
            confirmText =
                `Delete "${name}" permanently?\n\nThis cannot be undone.`;
        }

        if (!confirm(confirmText)) {
            return;
        }

        const headers = {};

        if (csrfToken) {
            headers["X-CSRF-Token"] = csrfToken;
        }

        try {

            const response = await fetch(
                `/admin/api/user-control/${id}/${action}`,
                {
                    method: "POST",
                    credentials: "same-origin",
                    headers
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error || "Action failed"
                );
            }

            message(
                data.message || "Action completed"
            );

            await loadUsers();

        } catch (error) {

            console.error(error);
            message(error.message, "error");
        }
    }


    function createPanel() {

        if (
            window.location.pathname.replace(/\/+$/, "")
            !== "/admin"
        ) {
            return;
        }

        if (document.getElementById("adminUserControl")) {
            return;
        }

        const main = getMain();

        if (!main) return;

        const section = document.createElement("section");

        section.id = "adminUserControl";
        section.className = "admin-user-panel";

        section.innerHTML = `
            <div class="admin-user-header">

                <div>
                    <h2>👥 User Management</h2>
                    <p>
                        Block, unblock and delete registered users.
                    </p>
                </div>

                <input
                    id="adminUserSearch"
                    class="admin-user-search"
                    placeholder="Search user..."
                >

            </div>

            <div
                id="adminUserMessage"
                class="admin-user-message"
            ></div>

            <div class="admin-user-table-wrap">

                <table class="admin-user-table">

                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Joined</th>
                            <th>Actions</th>
                        </tr>
                    </thead>

                    <tbody id="adminUsersBody">
                        <tr>
                            <td colspan="5">
                                Loading users...
                            </td>
                        </tr>
                    </tbody>

                </table>

            </div>
        `;

        main.prepend(section);


        section.addEventListener("click", event => {

            const button =
                event.target.closest("[data-action]");

            if (!button || button.disabled) return;

            runAction(
                button.dataset.action,
                button.dataset.id,
                button.dataset.name
            );
        });


        const search =
            document.getElementById("adminUserSearch");

        search.addEventListener("input", () => {

            const q =
                search.value.trim().toLowerCase();

            render(
                users.filter(user =>
                    (
                        user.name +
                        " " +
                        user.email
                    )
                    .toLowerCase()
                    .includes(q)
                )
            );
        });


        loadUsers();
    }


    document.addEventListener(
        "DOMContentLoaded",
        createPanel
    );

    setInterval(createPanel, 800);

})();
