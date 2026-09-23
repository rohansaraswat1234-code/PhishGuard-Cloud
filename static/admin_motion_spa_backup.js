(() => {

    const CONTENT_SELECTOR =
        "[data-admin-content], .admin-main, .main-content, .dashboard-main, main";

    function getContent(doc = document) {
        return doc.querySelector(CONTENT_SELECTOR);
    }

    function setActiveLink() {

        const current =
            window.location.pathname.replace(/\/+$/, "") || "/";

        document.querySelectorAll(
            ".sidebar a, .admin-sidebar a"
        ).forEach(link => {

            let path;

            try {
                path = new URL(
                    link.href,
                    window.location.origin
                ).pathname.replace(/\/+$/, "") || "/";
            } catch {
                return;
            }

            link.classList.toggle(
                "active",
                path === current
            );

            if (path === current) {
                link.setAttribute(
                    "aria-current",
                    "page"
                );
            } else {
                link.removeAttribute(
                    "aria-current"
                );
            }
        });
    }


    function showLoader() {

        let loader =
            document.querySelector(
                ".admin-nav-loader"
            );

        if (!loader) {

            loader =
                document.createElement("div");

            loader.className =
                "admin-nav-loader";

            document.body.appendChild(
                loader
            );
        }

        loader.classList.remove(
            "complete"
        );

        loader.classList.add(
            "loading"
        );
    }


    function finishLoader() {

        const loader =
            document.querySelector(
                ".admin-nav-loader"
            );

        if (!loader) return;

        loader.classList.remove(
            "loading"
        );

        loader.classList.add(
            "complete"
        );

        setTimeout(() => {
            loader.classList.remove(
                "complete"
            );
        }, 350);
    }


    function runScripts(container) {

        container
            .querySelectorAll("script")
            .forEach(oldScript => {

                const script =
                    document.createElement("script");

                for (
                    const attr of oldScript.attributes
                ) {
                    script.setAttribute(
                        attr.name,
                        attr.value
                    );
                }

                if (oldScript.src) {

                    const alreadyLoaded =
                        [...document.scripts]
                            .some(
                                s =>
                                s.src === oldScript.src
                            );

                    if (alreadyLoaded) {
                        oldScript.remove();
                        return;
                    }

                } else {

                    script.textContent =
                        oldScript.textContent;
                }

                oldScript.replaceWith(
                    script
                );
            });
    }


    function animateContent(content) {

        content.classList.remove(
            "admin-content-enter"
        );

        void content.offsetWidth;

        content.classList.add(
            "admin-content-enter"
        );
    }


    async function loadAdminPage(
        url,
        pushState = true
    ) {

        showLoader();

        try {

            const response =
                await fetch(url, {
                    credentials: "same-origin",
                    headers: {
                        "X-Admin-SPA": "1"
                    }
                });

            /*
             Login/session expired
            */
            if (
                response.redirected &&
                !new URL(response.url)
                    .pathname
                    .startsWith("/admin")
            ) {
                window.location.href =
                    response.url;
                return;
            }

            if (!response.ok) {
                throw new Error(
                    "HTTP " + response.status
                );
            }

            const html =
                await response.text();

            const parser =
                new DOMParser();

            const newDocument =
                parser.parseFromString(
                    html,
                    "text/html"
                );

            const currentContent =
                getContent(document);

            const newContent =
                getContent(newDocument);

            /*
             If page doesn't use our admin
             layout, use normal navigation.
            */
            if (
                !currentContent ||
                !newContent
            ) {
                window.location.href = url;
                return;
            }

            const imported =
                document.importNode(
                    newContent,
                    true
                );

            currentContent.replaceWith(
                imported
            );

            if (
                newDocument.title
            ) {
                document.title =
                    newDocument.title;
            }

            if (pushState) {

                history.pushState(
                    {},
                    "",
                    url
                );
            }

            setActiveLink();

            animateContent(
                imported
            );

            runScripts(
                imported
            );

            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });

            finishLoader();

        } catch (error) {

            console.error(
                "Admin navigation error:",
                error
            );

            /*
             Safe fallback
            */
            window.location.href = url;
        }
    }


    /*
     All admin navigation links
    */
    document.addEventListener(
        "click",
        event => {

            const link =
                event.target.closest("a");

            if (!link) return;

            if (
                link.target === "_blank" ||
                link.hasAttribute("download")
            ) {
                return;
            }

            let url;

            try {

                url =
                    new URL(
                        link.href,
                        window.location.origin
                    );

            } catch {
                return;
            }

            /*
             External links untouched
            */
            if (
                url.origin !==
                window.location.origin
            ) {
                return;
            }

            /*
             Only admin pages
            */
            if (
                !url.pathname.startsWith(
                    "/admin"
                )
            ) {
                return;
            }

            /*
             Login/logout should remain
             normal navigation.
            */
            if (
                url.pathname.includes(
                    "login"
                ) ||
                url.pathname.includes(
                    "logout"
                ) ||
                url.pathname.includes(
                    "register"
                )
            ) {
                return;
            }

            event.preventDefault();

            loadAdminPage(
                url.href,
                true
            );
        }
    );


    /*
     Browser back / forward
    */
    window.addEventListener(
        "popstate",
        () => {

            if (
                window.location.pathname
                    .startsWith("/admin")
            ) {

                loadAdminPage(
                    window.location.href,
                    false
                );
            }
        }
    );


    /*
     Initial page
    */
    document.addEventListener(
        "DOMContentLoaded",
        () => {

            setActiveLink();

            const content =
                getContent();

            if (content) {
                animateContent(
                    content
                );
            }
        }
    );

})();


/* Add Users Management link to admin sidebar */
document.addEventListener("DOMContentLoaded", () => {

    const sidebar =
        document.querySelector(
            ".admin-sidebar, .sidebar"
        );

    if (!sidebar) return;

    if (
        sidebar.querySelector(
            'a[href="/admin/users"]'
        )
    ) {
        return;
    }

    const nav =
        sidebar.querySelector("nav") ||
        sidebar;

    const usersLink =
        document.createElement("a");

    usersLink.href =
        "/admin/users";

    usersLink.textContent =
        "Users";

    const historyLink =
        nav.querySelector(
            'a[href="/admin/history"]'
        );

    if (historyLink) {
        historyLink.before(usersLink);
    } else {
        nav.appendChild(usersLink);
    }

});
