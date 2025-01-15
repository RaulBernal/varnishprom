vcl 4.1;
import std;
import directors;
import vsthrottle;

probe chaosprobe {
	.url = "/status";
	.timeout = 1s;
	.interval = 2s;
}
backend chaos1 {
        .host = "chaosbackend:8180";
		.probe = chaosprobe;
		.between_bytes_timeout = 2s;
		.first_byte_timeout = 2s;
		.connect_timeout = 1s;
}

backend chaos2 {
        .host = "chaosbackend:8181";
		.probe = chaosprobe;
		.between_bytes_timeout = 2s;
		.first_byte_timeout = 2s;
		.connect_timeout = 1s;

}

sub vcl_init {
    new chaos = directors.round_robin();
    chaos.add_backend(chaos1);
    chaos.add_backend(chaos2);
}

sub vcl_recv {
	unset req.http.cookie;
	if (req.url ~ "^/foo") {
		set req.backend_hint = chaos1;
	} else if(req.url ~ "^/bar") {
		set req.backend_hint = chaos2;
	} else {
		set req.backend_hint = chaos.backend();
	}
	set req.http.varnish-director = req.backend_hint;
}

sub vcl_hit {
	set req.http.varnish-cache = "HIT";
	if (obj.ttl <= 0s && obj.grace > 0s) {
		set req.http.cache = "STALE";
	}
}

sub vcl_miss {
	set req.http.varnish-cache = "MISS";
	if (vsthrottle.is_denied("apikey:" + client.ip, 1000,10s,30s)) {
		set req.http.varnish-cache = "THROTTLED";
	    return (synth(429, "Throttling Backend"));
	}
}

sub vcl_pass {
	set req.http.varnish-cache = "PASS";
}

sub vcl_pipe {
	set req.http.varnish-cache = "PIPE";
}

sub vcl_synth {
	set resp.http.varnish-cache = "SYNTH";
}

sub vcl_backend_fetch {
}

sub vcl_backend_response {
	set beresp.http.varnish-backend = beresp.backend;
}

sub vcl_backend_error {
	set beresp.http.varnish-cache = "BACKEND_ERROR";
}

sub vcl_deliver {
	if (obj.uncacheable) {
		set resp.http.varnish-cache = resp.http.varnish-cache + " uncacheable" ;
	}
	if (!resp.http.varnish-cache) {
		set resp.http.varnish-cache = req.http.varnish-cache;
	}	
	set resp.http.varnish-hits = obj.hits;
	set resp.http.varnish-director = req.http.varnish-director;
	set resp.http.varnish-backend = resp.http.varnish-backend;
	std.log("prom=backends backend=" + resp.http.varnish-backend + ",director="+ resp.http.varnish-director + ",cache=" + req.http.varnish-cache + ",status=" + resp.status +",desc=vcl_deliver");
}

