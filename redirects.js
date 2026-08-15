function isLocalDevelopmentHost(hostname) {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname.endsWith('.workers.dev');
}

function redirectForRequest(request) {
  const url = new URL(request.url);
  // Redirect decisions use the URL supplied by the runtime. Host,
  // CF-Connecting-IP, and MF-Original-Hostname are request headers and can be
  // spoofed by a client; none of them may turn a production HTTP request into
  // a local request. Wrangler tests use localhost/127.0.0.1 URLs directly.
  const localRequest = isLocalDevelopmentHost(url.hostname);
  if (url.hostname === 'checker.illek.ie') {
    url.hostname = 'email.illek.ie';
    url.protocol = 'https:';
    return Response.redirect(url.toString(), 308);
  }
  if (url.protocol === 'http:' && !localRequest) {
    url.protocol = 'https:';
    return Response.redirect(url.toString(), 308);
  }
  return null;
}

module.exports = { redirectForRequest };
