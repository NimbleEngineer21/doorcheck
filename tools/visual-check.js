// Development-only checks on the specimen, run in a real browser by CI.
// No scanned content is evaluated here.
(() => {
  const failures = [];
  if (document.documentElement.scrollWidth > window.innerWidth) failures.push("overflow");
  for (const row of document.querySelectorAll(".state")) {
    const mark = row.querySelector("svg");
    const content = row.querySelector("div");
    const label = row.querySelector("h3");
    const iconBox = mark.getBoundingClientRect();
    const textBox = content.getBoundingClientRect();
    const rtl = getComputedStyle(row.closest("section")).direction === "rtl";
    const separated = rtl ? iconBox.left >= textBox.right : iconBox.right <= textBox.left;
    if (!separated) failures.push("state order");
    if (!label.textContent.trim() || mark.getAttribute("aria-hidden") !== "true") {
      failures.push("state label");
    }
  }
  for (const value of document.querySelectorAll("bdi")) {
    if (getComputedStyle(value).unicodeBidi !== "isolate") failures.push("source isolation");
  }
  if (document.querySelectorAll(".state").length !== 18) failures.push("missing states");
  document.documentElement.dataset.visualCheck = failures.length ? failures.join(", ") : "pass";
})();
