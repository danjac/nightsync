import Vue from 'vue'
import Resource from 'vue-resource'
import App from './App'

import { getToken } from './auth'

Vue.use(Resource)

const jwtToken = getToken()

if (jwtToken) {
  Vue.http.headers.common['Authorization'] = 'Bearer ' + jwtToken
}

/* eslint-disable no-new */
new Vue({
  el: 'body',
  components: { App }
})
