// Monster Fitness — main.js

// Navbar scroll effect
const nav = document.getElementById('mainNav');
if (nav) {
  window.addEventListener('scroll', () => {
    nav.classList.toggle('scrolled', window.scrollY > 40);
  });
}

// Active nav link on scroll
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-link[href^="#"]');
window.addEventListener('scroll', () => {
  let current = '';
  sections.forEach(s => {
    if (window.scrollY >= s.offsetTop - 120) current = s.getAttribute('id');
  });
  navLinks.forEach(link => {
    link.classList.toggle('active', link.getAttribute('href') === '#' + current);
  });
});

// Animate elements on scroll
const observer = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting) { e.target.classList.add('visible'); }
  });
}, { threshold: 0.12 });

document.querySelectorAll('.area-card, .plan-card, .team-card, .about-stat-card, .schedule-card').forEach(el => {
  el.style.opacity = '0';
  el.style.transform = 'translateY(16px)';
  el.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
  observer.observe(el);
});

document.addEventListener('animationend', () => {}, false);

// Use IntersectionObserver to trigger visibility
const visObserver = new IntersectionObserver((entries) => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      e.target.style.opacity = '1';
      e.target.style.transform = 'translateY(0)';
      visObserver.unobserve(e.target);
    }
  });
}, { threshold: 0.1 });

document.querySelectorAll('.area-card, .plan-card, .team-card, .about-stat-card, .schedule-card').forEach(el => visObserver.observe(el));
