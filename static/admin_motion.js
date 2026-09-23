(() => {

    function setActiveLink() {

        const current =
            window.location.pathname.replace(/\/+$/, "") || "/";

        document.querySelectorAll(
            ".sidebar a, .admin-sidebar a"
        ).forEach(link => {

            try {

                const path =
                    new URL(
                        link.href,
                        window.location.origin
                    ).pathname.replace(/\/+$/, "") || "/";

                link.classList.toggle(
                    "active",
                    path === current
                );

            } catch {}
        });
    }


    document.addEventListener(
        "DOMContentLoaded",
        () => {

            setActiveLink();

            const content =
                document.querySelector(
                    "[data-admin-content], .admin-main, .main-content, .dashboard-main, main"
                );

            if (content) {

                content.classList.add(
                    "admin-content-enter"
                );
            }
        }
    );

})();
