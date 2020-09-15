# @TEST-DOC: Example of a Zeek test that runs a pcap and verifies output
# @TEST-EXEC: zeek -r $TRACES/http.pcap $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff http.log

event zeek_init()
	{
	# Remove the "origin" column from the HTTP log, it causes
	# log discrepancies between Bro 2.x and Zeek 3.
	local f = Log::get_filter(HTTP::LOG, "default");
	f$exclude=set("origin");
	Log::add_filter(HTTP::LOG, f);
	}

event zeek_done()
	{
	print "Goodbye world!";
	}
