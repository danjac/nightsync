<template>
  <div id="app" class="container">
    <div class="jumbotron text-center">
        <h1>Plans tonight?</h1>
        <p>See which bars are hoppin' tonight and RSVP ahead of time!
           Remember: take a cab and drink responsibly.</p>
    </div>
    <form @submit.prevent="search">
        <div class="form-group">
            <input type="text" class="form-control input-lg" placeholder="Where you at" v-model="location" />
        </div>
        <button type="submit" class="form-control btn btn-primary">Go</button>
    </form>
    <div class="media" v-for="bar in bars">
        <div class="media-left" v-show="bar.thumbnail">
            <img class="media-object" :src="bar.thumbnail" track-by="id" />
        </div>
        <div class="media-body">
            <h4 class="media-heading">
                <a href="">{{ bar.name }}</a>
                <button v-bind:class="bar.going ? 'btn pull-right' : 'btn btn-primary pull-right'" 
                        @click.prevent="send(bar.id)"
                        v-show="isAuth">Going: {{ bar.total }}</button>
                <a class="btn btn-primary pull-right" 
                   v-show="!isAuth" 
                   href="http://localhost:4000/auth/redirect/?provider=twitter">Going: {{ bar.total }}</a>
            </h4>
            <p v-show="bar.review"><em>"{{ bar.review }}"</em></p>
        </div>
    </div>
  </div>
</template>

<script>
import { getToken } from './auth'

const jwtToken = getToken()

export default {
  data () {
    return {
      bars: [],
      location: '',
      isAuth: jwtToken !== ''
    }
  },
  ready () {
    // we can't pass auth headers to a web socket, use query string instead
    this.$ws = new WebSocket(`ws://localhost:4000/ws/?jwt-token=${jwtToken}`)
    this.$ws.onmessage = event => {
      const msg = JSON.parse(event.data)
      this.bars = this.bars.map(bar => {
        if (msg.id === bar.id) {
          bar.total = msg.total
        }
        return bar
      })
    }
    this.location = window.localStorage.getItem('location') || ''
    if (this.location) {
      this.search()
    }
  },
  methods: {
    search () {
      // tbd: store location in localStorage
      if (!this.location) return
      this.$http.get(`http://localhost:4000/search/?location=${this.location}`)
      .then(response => {
        this.bars = response.data
        window.localStorage.setItem('location', this.location)
      })
    },
    send (id) {
      this.isAuth && this.$ws.send(id)
      this.bars = this.bars.map(bar => {
        if (id === bar.id) {
          bar.going = !bar.going
        }
        return bar
      })
    }
  }
}

</script>

<style>
@import "../node_modules/bootstrap/dist/css/bootstrap.min.css";
@import "../node_modules/bootstrap/dist/css/bootstrap-theme.min.css";
</style>
