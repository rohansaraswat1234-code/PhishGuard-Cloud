document.addEventListener(
    "DOMContentLoaded",
    () => {

        /* ======================================
           REVEAL ANIMATIONS
        ====================================== */

        const revealSelectors = [

            ".live-security-strip",
            ".security-insight-banner",

            ".user-stat-card",
            ".dashboard-panel",
            ".quick-action-card",
            ".danger-zone",
            ".personal-report-bar",

            ".scanner-system-bar",
            ".scanner-stat",
            ".scanner-card",

            ".security-strip",
            ".insight-banner",
            ".stat-card",
            ".profile-stat",
            ".analytics-panel",
            ".profile-hero",
            ".profile-stat",
            ".profile-panel"

        ];


        const elements =
            document.querySelectorAll(
                revealSelectors.join(",")
            );


        elements.forEach(
            (element, index) => {

                element.classList.add(
                    "pg-reveal"
                );


                element.style.setProperty(
                    "--pg-delay",
                    Math.min(
                        index * 45,
                        260
                    ) + "ms"
                );

            }
        );


        if (
            "IntersectionObserver"
            in window
        ) {

            const observer =
                new IntersectionObserver(
                    entries => {

                        entries.forEach(
                            entry => {

                                if (
                                    entry.isIntersecting
                                ) {

                                    entry.target
                                        .classList.add(
                                            "pg-visible"
                                        );


                                    observer.unobserve(
                                        entry.target
                                    );

                                }

                            }
                        );

                    },
                    {

                        threshold:
                            0.08,

                        rootMargin:
                            "0px 0px -35px 0px"

                    }
                );


            elements.forEach(
                element => {

                    observer.observe(
                        element
                    );

                }
            );

        }

        else {

            elements.forEach(
                element => {

                    element.classList.add(
                        "pg-visible"
                    );

                }
            );

        }



        /* ======================================
           SUBTLE 3D CARD TILT
        ====================================== */

        const tiltSelectors = [

            ".user-stat-card",
            ".quick-action-card",

            ".scanner-stat",

            ".stat-card",
            ".profile-stat"

        ];


        const tiltCards =
            document.querySelectorAll(
                tiltSelectors.join(",")
            );


        const allowTilt =
            window.matchMedia(
                "(min-width: 900px)"
            ).matches
            &&
            !window.matchMedia(
                "(prefers-reduced-motion: reduce)"
            ).matches;


        if (allowTilt) {

            tiltCards.forEach(
                card => {

                    card.classList.add(
                        "pg-tilt"
                    );


                    card.addEventListener(
                        "mousemove",
                        event => {

                            const rect =
                                card
                                    .getBoundingClientRect();


                            const x =
                                event.clientX
                                - rect.left;


                            const y =
                                event.clientY
                                - rect.top;


                            const centerX =
                                rect.width / 2;


                            const centerY =
                                rect.height / 2;


                            const rotateY =
                                (
                                    x
                                    - centerX
                                )
                                / centerX
                                * 2.3;


                            const rotateX =
                                -(
                                    y
                                    - centerY
                                )
                                / centerY
                                * 2.3;


                            card.style.transform =
                                `
                                perspective(900px)
                                rotateX(${rotateX}deg)
                                rotateY(${rotateY}deg)
                                translateY(-3px)
                                `;

                        }
                    );


                    card.addEventListener(
                        "mouseleave",
                        () => {

                            card.style.transform =
                                "";

                        }
                    );

                }
            );

        }

    }
);
