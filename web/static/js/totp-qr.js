(function () {
  var mount = document.getElementById("totp-qr");
  if (!mount || typeof qrcode !== "function") {
    return;
  }
  var uri = mount.getAttribute("data-otpauth-uri");
  if (!uri) {
    return;
  }
  var qr = qrcode(0, "M");
  qr.addData(uri);
  qr.make();
  mount.innerHTML = qr.createSvgTag(4, 0);
})();
