export function getToken () {
  let jwtToken = window.localStorage.getItem('jwt-token')
  if (!jwtToken) {
    const qs = {}
    window.location.search.substring(1).split('&').map(pair => {
      const kv = pair.split('=')
      qs[kv[0]] = kv[1]
    })
    jwtToken = qs['jwt-token']
    if (jwtToken) {
      window.localStorage.setItem('jwt-token', jwtToken)
    }
  }
  return jwtToken || ''
}
