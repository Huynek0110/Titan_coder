(function () {
  'use strict';
  try {
    var savedTheme = localStorage.getItem('codepilot.theme');
    if (savedTheme === 'light' || savedTheme === 'dark') document.documentElement.dataset.theme = savedTheme;
  } catch (_) {}
}());
