(function() {
  var theme = 'light'
  try {
    var saved = localStorage.getItem('auth-theme')
    if (saved) {
      theme = saved
    }
  } catch(e) {}
  if (theme === 'dark' || (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark')
  }
})()
