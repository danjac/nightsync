import Vue from 'vue'
import Resource from 'vue-resource'
import App from './App'

import { getToken } from './auth'

const unauthorized = {
  response (res) {
    if (res && res.status === 401) {
      window.localStorage.removeItem('jwt-token')
    }
    return res
  }
}

Vue.use(Resource)
Vue.http.interceptors.push(unauthorized)

const jwtToken = getToken()

if (jwtToken) {
  Vue.http.headers.common['Authorization'] = 'Bearer ' + jwtToken
}

/* eslint-disable no-new */
new Vue({
  el: 'body',
  components: { App }
})
