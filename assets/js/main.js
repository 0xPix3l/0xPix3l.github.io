document.addEventListener('DOMContentLoaded', function () {
  // ── Hamburger menu ──
  var sidebar = document.getElementById('sidebar');
  var openBtn = document.getElementById('hamburger-open');
  var closeBtn = document.getElementById('hamburger-close');
  var overlay = document.getElementById('sidebar-overlay');
  var mobileToc = document.getElementById('mobile-toc');
  var tocOverlay = document.getElementById('toc-overlay');
  var tocCloseBtn = document.getElementById('mobile-toc-close');
  var isPostPage = !!document.querySelector('.post-body');

  function openMenu() {
    if (isPostPage && mobileToc) {
      // On post pages, hamburger opens TOC
      mobileToc.classList.add('mobile-toc', 'open');
      tocOverlay && tocOverlay.classList.add('open');
    } else {
      // On other pages, open sidebar
      sidebar && sidebar.classList.add('open');
      overlay && overlay.classList.add('open');
    }
    document.body.style.overflow = 'hidden';
  }
  function closeMenu() {
    sidebar && sidebar.classList.remove('open');
    overlay && overlay.classList.remove('open');
    if (mobileToc) {
      mobileToc.classList.remove('open');
      tocOverlay && tocOverlay.classList.remove('open');
    }
    document.body.style.overflow = '';
  }

  openBtn && openBtn.addEventListener('click', openMenu);
  closeBtn && closeBtn.addEventListener('click', closeMenu);
  overlay && overlay.addEventListener('click', closeMenu);
  tocOverlay && tocOverlay.addEventListener('click', closeMenu);
  tocCloseBtn && tocCloseBtn.addEventListener('click', closeMenu);

  // Close menu when clicking TOC links
  if (mobileToc) {
    mobileToc.querySelectorAll('.toc-nav a').forEach(function (a) {
      a.addEventListener('click', closeMenu);
    });
  }

  document.querySelectorAll('.left-nav .nav-links a').forEach(function (a) {
    a.addEventListener('click', closeMenu);
  });

  // ── TOC generation ──
  var tocNav = document.getElementById('toc-nav');
  var postBody = document.querySelector('.post-body');
  if (tocNav && postBody) {
    var headings = postBody.querySelectorAll('h2, h3');
    headings.forEach(function (h, i) {
      if (!h.id) h.id = 'heading-' + i;
      var a = document.createElement('a');
      a.href = '#' + h.id;
      a.textContent = h.textContent.replace(/^#{2,4}\s*/, '');
      if (h.tagName === 'H3') a.classList.add('toc-h3');
      tocNav.appendChild(a);
    });

    var tocLinks = tocNav.querySelectorAll('a');
    window.addEventListener('scroll', function () {
      var current = '';
      headings.forEach(function (h) {
        if (h.getBoundingClientRect().top < 120) current = h.id;
      });
      tocLinks.forEach(function (a) {
        a.classList.toggle('active', a.getAttribute('href') === '#' + current);
      });
    });
  }

  // ── Wrap code blocks with language label ──
  document.querySelectorAll('.post-body div.highlighter-rouge, .post-body div.highlight').forEach(function (div) {
    // Detect language from class
    var lang = '';
    var classes = div.className.split(/\s+/);
    for (var i = 0; i < classes.length; i++) {
      if (classes[i].startsWith('language-')) {
        lang = classes[i].replace('language-', '');
        break;
      }
    }

    // Fallback: check inner <code>
    if (!lang) {
      var code = div.querySelector('pre code');
      if (code) {
        var codeClasses = code.className.split(/\s+/);
        for (var j = 0; j < codeClasses.length; j++) {
          if (codeClasses[j].startsWith('language-')) {
            lang = codeClasses[j].replace('language-', '');
            break;
          }
        }
      }
    }

    // Create wrapper
    var wrapper = document.createElement('div');
    wrapper.className = 'code-block-wrapper';

    if (lang) {
      var label = document.createElement('span');
      label.className = 'code-lang-label';
      label.textContent = lang;
      wrapper.appendChild(label);
    }

    // Move the pre into the wrapper
    div.parentNode.insertBefore(wrapper, div);
    var pre = div.querySelector('pre');
    if (pre) {
      wrapper.appendChild(pre);
    }
    div.remove();

    // Copy button
    var btn = document.createElement('button');
    btn.className = 'code-copy';
    btn.textContent = 'copy';
    btn.addEventListener('click', function () {
      var codeEl = pre.querySelector('code') || pre;
      navigator.clipboard.writeText(codeEl.textContent).then(function () {
        btn.textContent = 'copied!';
        setTimeout(function () { btn.textContent = 'copy'; }, 1500);
      });
    });
    wrapper.appendChild(btn);
  });

  // ── Scroll-to-top button (mobile) ──
  var scrollBtn = document.createElement('button');
  scrollBtn.className = 'scroll-to-top';
  scrollBtn.innerHTML = '&#x2191;';
  scrollBtn.setAttribute('aria-label', 'Scroll to top');
  document.body.appendChild(scrollBtn);

  window.addEventListener('scroll', function () {
    scrollBtn.classList.toggle('visible', window.scrollY > 400);
  });
  scrollBtn.addEventListener('click', function () {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
});
