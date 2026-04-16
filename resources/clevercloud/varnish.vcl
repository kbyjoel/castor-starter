sub vcl_recv {

    if (req.url ~ "\.(jpg|jpeg|png|gif|ico|css|js|svg|woff|eot|ttf|swf)") {
        return (pass);
    }

    if (req.url ~ "/_profiler/.*$") {
        return (pass);
    }

    if (req.url ~ "/inch-circumstance-paradox/.*$") {
        return (pass);
    }

    if (req.method == "BAN") {
        if (req.http.Cache-Tags) {
            ban("obj.http.Cache-Tags ~ " + req.http.Cache-Tags);
        } elseif (req.http.X-Host) {
            ban("obj.http.X-Url ~ " + req.http.X-Url + " && obj.http.X-Host ~ " + req.http.X-Host);
        } else {
            ban("obj.http.X-Url ~ " + req.http.X-Url);
        }

        return (synth(200, "Banned"));
    }

    # Remove tracking query params
    if (req.url ~ "(\?|&)(gclid|cx|ie|cof|siteurl|zanpid|origin|fbclid|sfmc_[a-z]+|mc_[a-z]+|utm_[a-z]+|_bta_[a-z]+|gad_[a-z]+|source|sscid|sapa)=") {
        set req.url = regsuball(req.url, "(gclid|cx|ie|cof|siteurl|zanpid|origin|fbclid|sfmc_[a-z]+|mc_[a-z]+|utm_[a-z]+|_bta_[a-z]+|gad_[a-z]+|source|sscid|sapa)=[-_A-z0-9+()%.]+&?", "");
        set req.url = regsub(req.url, "[?|&]+$", "");
    }

    if (req.restarts == 0 && (req.http.accept ~ "application/vnd.fos.user-context-hash" || req.http.x-user-context-hash)) {
        return (synth(400));
    }

    if (req.http.cookie) {
        # strip all cookies that are not relevant to the backend, to avoid cacche poisoning with every cookie combination
        set req.http.cookie = ";" + req.http.cookie;
        set req.http.cookie = regsuball(req.http.cookie, "; +", ";");
        set req.http.cookie = regsuball(req.http.cookie, ";(PHPSESSID|tlw_cart|tlw_updated)=", "; \1=");
        set req.http.cookie = regsuball(req.http.cookie, ";[^ ][^;]*", "");
        set req.http.cookie = regsuball(req.http.cookie, "^[; ]+|[; ]+$", "");

        if (req.http.cookie == "") {
            unset req.http.cookie;
        }
    }

    if (req.http.Authorization) {
        return (pass);
    }
    if (req.http.cookie) {
        # temporary, for test purposes, will add user context hash later
        return (pass);
    }

    set req.http.Surrogate-Capability = "abc=ESI/1.0";
    # Lookup the context hash if there are credentials on the request
    # Only do this for cacheable requests. Returning a hash lookup discards the request body.
    # https://www.varnish-cache.org/trac/ticket/652

    if (req.method == "PRI") {
        /* We do not support SPDY or HTTP/2.0 */
        return (synth(405));
    }

    if (req.method != "GET" && req.method != "HEAD"
        && req.method != "PUT" && req.method != "POST"
        && req.method != "TRACE" && req.method != "OPTIONS"
        && req.method != "DELETE") {
        /* Non-RFC2616 or CONNECT which is weird. */
        return (pipe);
    }

    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    return (hash);
}

sub vcl_backend_response {

    set beresp.http.X-Url = bereq.url;
    set beresp.http.X-Host = bereq.http.host;

    if (beresp.http.surrogate-control ~ "ESI/1.0") {
        unset beresp.http.surrogate-control;
        set beresp.do_esi = true;
    }

    if (beresp.status >= 500 && bereq.is_bgfetch) {
        return (abandon);
    }
    if (bereq.uncacheable) {
        return (deliver);
    }
    if (
        beresp.ttl <= 0s
        || beresp.http.Cache-Control ~ "no-cache|no-store|private"
        || beresp.http.Set-Cookie
        || beresp.http.Vary == "*"
    ) {
        set beresp.ttl = 120s;
        set beresp.uncacheable = true;
        return (deliver);
    }

    # Allow stale content, in case the backend goes down.
    # make Varnish keep all objects for 24 hours beyond their TTL
    set beresp.grace = 24h;

    return (deliver);
}

