(function() {
  var theme = 'professional'
  try {
    var saved = localStorage.getItem('auth-theme')
    if (saved === 'professional' || saved === 'dark' || saved === 'auto' || saved === 'light') {
      theme = saved
    }
  } catch(e) {}
  if (theme === 'dark' || (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark')
  }
  document.documentElement.removeAttribute('data-theme')
})()
