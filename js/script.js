// Toggle Menu Mobile
const navbarNav = document.querySelector('.navbar-nav');
const menuHam = document.querySelector('#menuham');

if (menuHam) {
  menuHam.onclick = (e) => {
    e.preventDefault();
    navbarNav.classList.toggle('active');
  };

  document.addEventListener('click', function (e) {
    if (!menuHam.contains(e.target) && !navbarNav.contains(e.target)) {
      navbarNav.classList.remove('active');
    }
  });
}

// LOGIKA TOGGLE TEMA GELAP / TERANG SMOOTH
const themeToggleBtn = document.getElementById('themeToggle');
const htmlElement = document.documentElement;

// Cek simpanan tema pengguna
const savedTheme = localStorage.getItem('theme') || 'dark';
htmlElement.setAttribute('data-theme', savedTheme);

if (themeToggleBtn) {
  themeToggleBtn.addEventListener('click', () => {
    const currentTheme = htmlElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    // Set tema baru
    htmlElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
  });
}
