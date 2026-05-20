document.documentElement.classList.add("js");

const revealObserver = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        revealObserver.unobserve(entry.target);
      }
    });
  },
  {
    threshold: 0.14,
  },
);

document.querySelectorAll(".reveal").forEach((section) => {
  revealObserver.observe(section);
});

const links = [...document.querySelectorAll(".nav__links a")];
const sections = links
  .map((link) => document.querySelector(link.getAttribute("href")))
  .filter((section) => section instanceof HTMLElement);

const linkMap = new Map(links.map((link) => [link.getAttribute("href")?.slice(1), link]));

links[0]?.classList.add("is-active");

const navObserver = new IntersectionObserver(
  (entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((left, right) => right.intersectionRatio - left.intersectionRatio)[0];

    if (!visible) {
      return;
    }

    const id = visible.target.getAttribute("id");
    links.forEach((link) => link.classList.remove("is-active"));
    linkMap.get(id)?.classList.add("is-active");
  },
  {
    rootMargin: "-20% 0px -60% 0px",
    threshold: [0.2, 0.45, 0.7],
  },
);

sections.forEach((section) => {
  navObserver.observe(section);
});
