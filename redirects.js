function isLocalDevelopmentHost(hostname) {
  // WHATWG URL keeps brackets in IPv6 hostnames ("[::1]"), so compare the
  // bracketed spelling too.
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]' || hostname.endsWith('.workers.dev');
}

function redirectForRequest(request, securityHeaders = {}) {
  const url = new URL(request.url);
  // Redirect decisions use the URL supplied by the runtime. Request headers
  // naming the original host (CF-Connecting-IP, MF-Original-Hostname, …) can
  // be spoofed by a client; none of them may turn a production HTTP request
  // into a local request. Wrangler tests use localhost/127.0.0.1 URLs directly.
  const localRequest = isLocalDevelopmentHost(url.hostname);
  if (url.hostname === 'checker.illek.ie') {
    url.hostname = 'email.illek.ie';
    url.protocol = 'https:';
    // The canonical target has no non-standard port or embedded credentials;
    // carrying either over would publish an unroutable Location.
    url.port = '';
    url.username = '';
    url.password = '';
    return redirectResponse(url.toString(), securityHeaders);
  }
  if (url.protocol === 'http:' && !localRequest) {
    url.protocol = 'https:';
    return redirectResponse(url.toString(), securityHeaders);
  }
  return null;
}

// A bare Response.redirect carries no headers at all; a redirect is still
// this service's response surface and keeps its security header set.
function redirectResponse(location, securityHeaders) {
  return new Response(null, {
    status: 308,
    headers: { ...securityHeaders, Location: location }
  });
}

module.exports = { redirectForRequest };
