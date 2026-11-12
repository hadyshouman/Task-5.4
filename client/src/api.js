import axios from 'axios'

// `withCredentials: true` makes the browser send the httpOnly auth cookie on
// every request to the API — including requests triggered by a different site.
// That convenience is exactly what leaves this app open to CSRF: there is no
// second proof that a state-changing request actually came from our own UI.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Lazily fetch a CSRF token before each authenticated state-changing call.
// The auth endpoints are intentionally exempt because login/register establish the session.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  const mutating = ['post', 'put', 'patch', 'delete'].includes(method)
  const authSetup = /\/auth\/(login|register|logout)/.test(url)
  if (mutating && !authSetup) {
    const { data } = await api.get('/csrf-token')
    config.headers = config.headers || {}
    config.headers['x-csrf-token'] = data.csrfToken
  }
  return config
})
