(function() {
  var theme = 'light'
  try {
    var saved = localStorage.getItem('auth-theme')
    if (saved) {
      theme = saved
    }
  } catch(e) {}
  if (theme === 'light' || (theme === 'auto' && window.matchMedia('(prefers-color-scheme: light)').matches)) {
    document.documentElement.classList.add('light')
  }
})()
