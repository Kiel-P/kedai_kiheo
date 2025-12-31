// toggle menu
const navbarNav = document.querySelector('.navbar-nav');
// menu hamberger
document.querySelector('#menuham').onclick = () => {
  navbarNav.classList.toggle('active');
};
// asal klik menu hilangin
const hamberger = document.querySelector('#menuham');
document.addEventListener('click', function (e) {
  if (!hamberger.contains(e.target) && !navbarNav.contains(e.target)) {
    navbarNav.classList.remove('active');
  }
});
