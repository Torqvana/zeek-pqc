@load base/protocols/ssl
@load base/protocols/ssh

module PQC;

export {
    redef record SSL::Info += {
        is_pqc: bool       &log &optional;
    };

    redef record SSH::Info += {
        is_pqc: bool        &log &optional;
    };

	redef enum Log::ID += { LOG };

	type Info: record {
		uid:                string                  &log;
        host:               addr                    &log;
		is_client:          bool                    &log;
        is_hybrid:          bool                    &log &optional;
        service:            string                  &log &optional;
		pqc_algs:           vector of string        &log;
	};
}

# Use of the ssl_extension_key_share event to identify support for PQC algorithms in TLS 1.3 key share extension
event ssl_extension_key_share(c: connection, is_client: bool, curves: index_vec)
    {
        local pqc_val: vector of string;
        local pqc_host: addr;
        local is_hybrid = F;

        for ( i in curves )
            {
                local cv_val = curves[i];
                if ( cv_val in pqc_tls_curves )
                    {
                        pqc_val += pqc_tls_curves[cv_val];
                    }
                if ( cv_val in pqc_tls_hybrid_curves )
                    {
                        pqc_val += pqc_tls_hybrid_curves[cv_val];
                        is_hybrid = T;
                    }
            }
        if ( |pqc_val| > 0 )
            {
                pqc_host = is_client ? c$id$orig_h : c$id$resp_h;
                local rec: PQC::Info = [$uid=c$uid, $host=pqc_host, $is_client=is_client, $is_hybrid=is_hybrid, $service="ssl", $pqc_algs=pqc_val];
                Log::write(PQC::LOG, rec);
            }
    }
# Use ssl established event to determine if PQC algorithms were selected during the negociation
event ssl_established(c: connection)
    {
        if ( c?$ssl && c$ssl?$curve )
            {
                c$ssl$is_pqc = F;
                for ( i in pqc_tls_curves )
                    {
                        if ( c$ssl$curve == pqc_tls_curves[i] )
                            {
                                c$ssl$is_pqc = T;
                            }
                    }
                for ( i in pqc_tls_hybrid_curves )
                    {
                        if ( c$ssl$curve == pqc_tls_hybrid_curves[i] )
                            {
                                c$ssl$is_pqc = T;
                            }
                    }
            }
    }

# Use ssh_capabilities to identify the PQC algorithms advertised by the client or server during the establishment of the SSH session
event ssh_capabilities(c: connection, cookie: string, capabilities: SSH::Capabilities)
    {
        local pqc_val: vector of string;
        local pqc_host: addr;
        local is_hybrid = F;

        if ( |capabilities| > 0 && capabilities?$kex_algorithms && |capabilities$kex_algorithms| > 0 )
            {
                for ( i, cap in capabilities$kex_algorithms )
                    {
                        if ( cap in pqc_ssh_curves )
                            {
                                pqc_val += cap;
                            }
                        if ( cap in pqc_ssh_hybrid_curves )
                            {
                                pqc_val += cap;
                                is_hybrid = T;
                            }
                    }
            }
        if ( |pqc_val| > 0 && capabilities?$is_server )
            {
                pqc_host = capabilities$is_server ? c$id$resp_h : c$id$orig_h;
                local rec: Pqc::Info = [$uid=c$uid, $host=pqc_host, $is_client=!capabilities$is_server, $is_hybrid=is_hybrid, $service="ssh", $pqc_algs=pqc_val];
                Log::write(Pqc::LOG, rec);
            }
        if ( c?$ssh && c$ssh?$kex_alg )
            {
                c$ssh$is_pqc = F;
                if ( c$ssh$kex_alg in pqc_ssh_curves )
                    {
                        c$ssh$is_pqc = T;
                    }
                if ( c$ssh$kex_alg in pqc_ssh_hybrid_curves )
                    {
                        c$ssh$is_pqc = T;
                    }
            }
    }

event zeek_init()
    {
        Log::create_stream(PQC::LOG, [$columns=Info, $path="pqc"]);

    }
