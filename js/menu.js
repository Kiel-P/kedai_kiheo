const toggleBtn = document.getElementById("lainToggle");
const menu = document.getElementById("lainMenu");

let isOpen = false;
let timer = null;
const DELAY = 50;

toggleBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  if (timer) return;

  timer = setTimeout(() => {
    if (isOpen) {
      menu.classList.remove("show");
    } else {
      menu.classList.add("show");
    }

    isOpen = !isOpen;
    timer = null;
  }, DELAY);
});

/* Klik di luar menu -> tutup */
document.addEventListener("click", (e) => {
  if (
    isOpen &&
    !menu.contains(e.target) &&
    !toggleBtn.contains(e.target)
  ) {
    if (timer) return;

    timer = setTimeout(() => {
      menu.classList.remove("show");
      isOpen = false;
      timer = null;
    }, DELAY);
  }
});
