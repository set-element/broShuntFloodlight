module Floodlight;
redef exit_only_after_terminate=T;

export {

	redef enum Notice::Type += {
		FloodlightSkipFlow,
		};


	const fl_host = "localhost" &redef; 		#
	const fl_port = "8080" &redef; 			#
	const fl_url = "/wm/firewall/rules/json" &redef;#
	#
	const method = "POST" &redef; 			#
	# data for flow to be /blocked/
	const dl_type = "IPv4" &redef; 			# alt is "ARP"
	const nw_proto = "TCP" &redef; 			# alt = UDP|ICMP
	const priority = "10" &redef; 			#
	const action = "DENY" &redef; 			# alt ALLOW

	global shunt_count = 0 &redef; 			# keep track of the total number of active shunts to
	const  shunt_count_threshold = 2000 &redef; 	#  make sure it does not exceed this value.

	const timeout_value = 10sec &redef;
	

	global shunt: function(c: connection, enttype: string, dtime: double);
	global restore: function(c: connection);

	type Request: record {
		url: string; 		# request URL
		method: string; 	# request method
		client_data: string; 	# floodlight "command" data - stdin for cmd
		cmd: string;		# whole curl command
		id: string;		# from triggering connection
		dtime: double;		# initial timestamp
		};

	type shunt_entity: record {
		ent_ruleid: set[int]; 		# value returned from floodlight, can be more than one per c$uid
		ent_time: double &default = 0.0; 	# for manually walking and reaping the 
							#  state table
		};
	
	global shunt_library: table[string] of shunt_entity;
	global request: event(req: Floodlight::Request);

}

## Extract integer (or quoted string) value from a key:value (or key:"value").
# DATA: {"status" : "Rule added", "rule-id" : "1533907586"}
function extract_value(str: string) : string
{
	local s = split1(str, /:/)[2];
	s = sub(s, /^\"/, ""); #"
	return sub(s, /\"$/, ""); #"
}

## Extract text between the last two two double quotes.
function extract_last_quoted(str: string) : string
{
	local q = find_last(str, /\"([^\"]|\\\")*\"/); # "
	return split(q, /\"/)[2]; # "
}

function parse_message(data: string) : int
{
	local status = "UNKNOWN";
	local rule_id = "0";
 
	local array = split(data, /, \"/); # "

	for ( i in array ) {

		local val = array[i];

		if ( strstr(val, "status\" :") > 0 )
			status = extract_value(val);
		else if ( strstr(val, "rule-id\" :") > 0 )
			rule_id = extract_value(val);
		}

	print fmt("status: %s    rule_id: %s", status, rule_id);
	return( |to_int(rule_id)|);
	} 

event request(req: Request)
	{
	local data: vector of string = vector();
	
	when ( local result = Exec::run([$cmd=req$cmd]) )
		{
		if ( result?$stdout )
			data = result$stdout;
		else
			print fmt("NO STDOUT");

		for ( i in data )
			{
			print fmt("DATA: %s", data[i]);
			local check = parse_message(data[i]);

			if ( check > 0 ) {
				# "legitimate" add, now for some bookeeping ...
				++shunt_count;
				# add connection id to the big list by hook or crook ;-)
				if ( req$id in shunt_library ) {
					# can have more than one flow like operations on a single
					#  connection.
					add shunt_library[req$id]$ent_ruleid[check];
					print fmt("Augmented record %s %s", shunt_library[req$id], req$id);
					}
				else {
					local t_shunt_entity: shunt_entity;

					t_shunt_entity$ent_ruleid = set();
					add t_shunt_entity$ent_ruleid[check];
					t_shunt_entity$ent_time = req$dtime;
				
					shunt_library[req$id] = t_shunt_entity;
					print fmt("Insert record %s %s", t_shunt_entity, req$id);
					}


				} # check > 0
			} # end for i in data

		print fmt("D: %s", result$stdout);
		
		}
	}

function shunt(c: connection, enttype: string, dtime: double)
{
	# Initial sanity check - are we shunting a little too much?
	if ( shunt_count == shunt_count_threshold ) {
		NOTICE([$note=FloodlightSkipFlow, $conn=c,
			$msg=fmt("Floodlight session threshold exceeded at %s", shunt_count_threshold)]);
		return;
		}

	# request structure - the firewall sequence will be put
	#   in the req$client_data string field.
	#
	local req: Request;
	local RC = str_shell_escape("%{http_code}");
	req$url = fmt("http://%s:%s%s", fl_host, fl_port, fl_url);
	req$method = method;
	req$dtime = dtime;
	req$id = c$uid;

	local aux_info = fmt(" \"nw-proto\": \"%s\", \"action\": \"%s\", \"dl-type\": \"%s\", ", nw_proto, action, dl_type);

	if ( enttype == "IP_PAIR" ) {
		# Build the request structure for a {sip:dip} connection.
		req$client_data = fmt("\'\{ %s \"src-ip\": \"%s\", \"dst-ip\": \"%s\" \}\' ", aux_info, c$id$orig_h, c$id$resp_h);
		}
	else if ( enttype == "ORIG" ) {
		# Build the request structure for a {sip:sp:dip:dp} connection.
		req$client_data = fmt("\'\{ %s \"src-ip\": \"%s\", \"dst-ip\": \"%s\",  \"tp-src\": \"%s\", \"tp-dst\": \"%s\"  \}\' ", aux_info, c$id$orig_h, c$id$resp_h, port_to_count(c$id$orig_p), port_to_count(c$id$resp_p));

		}
	else if ( enttype == "RESP" ) {
		# Build the request structure for a {dip:dp:sip:sp} connection.
		req$client_data = fmt("\'\{ %s \"src-ip\": \"%s\", \"dst-ip\": \"%s\",  \"tp-src\": \"%s\", \"tp-dst\": \"%s\"  \}\' ", aux_info, c$id$resp_h, c$id$orig_h, port_to_count(c$id$resp_p), port_to_count(c$id$orig_p));

		}
	else {
		print fmt("UNKNOWN shunt request type: %s", enttype);
		return;
		}

	# -s: silent, -g: globbing off, 
	local cmd = fmt("curl -g -X \"%s\"", method);
	# add timeout
	cmd = fmt("%s -m %.0f", cmd, timeout_value);
	# this is in prep for the client data
	cmd = fmt("%s -d %s", cmd, req$client_data);
	# add on the floodlight URL
	cmd = fmt("%s \"%s\"", cmd, str_shell_escape(req$url));
print fmt("%s", cmd);
	req$cmd = cmd;	
	event Floodlight::request(req);
}

function restore(c: connection)
{
	# remove all shunts related to the c$uid
	if ( c$uid in shunt_library ) {
		local t_shunt_entity = shunt_library[c$uid];

		# loop over the set of ruleid values for the connection id
		# {"status" : "Rule deleted"}
		for ( i in t_shunt_entity$ent_ruleid ) {
			local req: Request;
			req$url = fmt("http://%s:%s%s", fl_host, fl_port, fl_url);
			req$id = c$uid;
			req$client_data = fmt("\'\{ \"ruleid\": \"%s\" \}\'", t_shunt_entity$ent_ruleid[i]);
			
			local cmd = fmt("curl -g -X \"DELETE\" ");
			cmd = fmt("%s -m %.0f", cmd, timeout_value);
			cmd = fmt("%s -d %s", cmd, req$client_data);
			cmd = fmt("%s \"%s\"", cmd, str_shell_escape(req$url));

			req$cmd = cmd;
			print fmt("restore: %s", cmd);
		        event Floodlight::request(req);
			}		
			

		delete shunt_library[c$uid];
		}
	else {
		print fmt("restore index %s not in library", c$uid);
		}
}

event bro_init()
{
	print "starting test ...";
	local c: connection;
	local c_id: conn_id;

	c_id$orig_h = 128.45.1.3;
	c_id$orig_p = to_port("138/tcp");
	c_id$resp_h = 123.113.10.220;
	c_id$resp_p = to_port("13800/tcp");

	c$uid = "Ctrr4t2Xgv2rz6xdra";
	c$id = c_id;

	shunt(c, "ORIG", 1409641189.660239);

	restore(c);
}
