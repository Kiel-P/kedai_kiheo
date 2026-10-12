// Toggle Hamburger Menu Mobile
const navbarNav = document.querySelector('.navbar-nav');
const menuHam = document.querySelector('#menuham');

menuHam.onclick = (e) => {
  e.preventDefault();
  navbarNav.classList.toggle('active');
};

// Klik di luar menu untuk menutup navbar mobile
document.addEventListener('click', function (e) {
  if (!menuHam.contains(e.target) && !navbarNav.contains(e.target)) {
    navbarNav.classList.remove('active');
  }
});

// ==========================================
// DARK / LIGHT THEME TOGGLE LOGIC
// ==========================================
const themeToggleBtn = document.getElementById('themeToggle');
const htmlElement = document.documentElement;

// Cek tema tersimpan di localStorage atau default 'dark'
const savedTheme = localStorage.getItem('theme') || 'dark';
htmlElement.setAttribute('data-theme', savedTheme);

themeToggleBtn.addEventListener('click', () => {
  const currentTheme = htmlElement.getAttribute('data-theme');
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  
  htmlElement.setAttribute('data-theme', newTheme);
  localStorage.setItem('theme', newTheme);
  
  // Re-initialize feather icons jika diperlukan
  if (window.feather) {
    feather.replace();
  }
});
