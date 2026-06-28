// 导航栏滚动效果
const navbar = document.querySelector('.navbar');
window.addEventListener('scroll', () => {
  navbar.classList.toggle('scrolled', window.scrollY > 20);
});

// 移动端菜单
const navToggle = document.querySelector('.nav-toggle');
const navLinks = document.querySelector('.nav-links');

navToggle.addEventListener('click', () => {
  navLinks.classList.toggle('active');
  navToggle.classList.toggle('active');
});

// 点击链接关闭菜单
navLinks.querySelectorAll('a').forEach(link => {
  link.addEventListener('click', () => {
    navLinks.classList.remove('active');
    navToggle.classList.remove('active');
  });
});

// 滚动时高亮当前section
const sections = document.querySelectorAll('section[id]');
const navItems = document.querySelectorAll('.nav-links a');

function highlightNav() {
  const scrollY = window.scrollY + 100;

  sections.forEach(section => {
    const top = section.offsetTop;
    const height = section.offsetHeight;
    const id = section.getAttribute('id');

    if (scrollY >= top && scrollY < top + height) {
      navItems.forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('href') === `#${id}`) {
          item.classList.add('active');
        }
      });
    }
  });
}

window.addEventListener('scroll', highlightNav);

// 卡片进入动画
const observerOptions = {
  threshold: 0.1,
  rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.style.opacity = '1';
      entry.target.style.transform = 'translateY(0)';
      observer.unobserve(entry.target);
    }
  });
}, observerOptions);

document.querySelectorAll('.column-card, .team-card, .contact-card, .step').forEach((el, i) => {
  el.style.opacity = '0';
  el.style.transform = 'translateY(20px)';
  el.style.transition = `opacity 0.5s ${i * 0.08}s, transform 0.5s ${i * 0.08}s`;
  observer.observe(el);
});

// Check submit status
fetch('/api/submit-status')
  .then(r => r.json())
  .then(data => {
    const btn = document.getElementById('submitBtn');
    if (data.open) {
      btn.textContent = '立即投稿';
      btn.href = '/admin';
    } else {
      btn.textContent = '投稿未开放';
      btn.href = 'javascript:void(0)';
      btn.style.opacity = '0.6';
    }
  })
  .catch(() => {});

// 平滑滚动
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});
