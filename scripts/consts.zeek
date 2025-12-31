module PQC;

export {

    const pqc_tls_curves: table[count] of string = {
		[512] = "MLKEM512",
		[513] = "MLKEM768",
		[514] = "MLKEM1024"
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

	const pqc_tls_hybrid_curves: table[count] of string = {
		[4587] = "SecP256r1MLKEM768",
		[4588] = "X25519MLKEM768",
		[4589] = "SecP384r1MLKEM1024",
		[25497] = "X25519Kyber768Draft00", # draft-tls-westerbaan-xyber768d00-02
		[25498] = "SecP256r1Kyber768Draft00", # draft-kwiatkowski-tls-ecdhe-kyber-01
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;

    const pqc_ssh_curves: set[string] = {
	    "mlkem1024nistp384-sha384",
	    "mlkem768nistp256-sha256"
    } &redef;

    const pqc_ssh_hybrid_curves: set[string] = {
	    "sntrup761x25519-sha512",
	    "sntrup761x25519-sha512@openssh.com",
	    "mlkem768x25519-sha256"
    } &redef;
    
}