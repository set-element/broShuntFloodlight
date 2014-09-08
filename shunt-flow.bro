# Prototype software shunt, Scott Campbell, scampbell@lbl.gov
#
# This script assumes that the following change is made
#   bro:id:`use_conn_size_analyzer` = T
#
#
@load /home/scottc/development/floodlight/BRO_INSTALL/tmp/flood1.bro
redef use_conn_size_analyzer = T;

module Shunt;

export {

	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		ShuntTrackerIncrement,
		ShuntTrackerHWater,
		ShuntTrackerLWater,
		ShuntClear,
		ShuntTrigger,
		ShuntFlowIPIgnore,
		};

	type Info: record {
		pr_time: double &default=0.0 &log;	# trigger time
		index: string &default="NULL" &log;	# index value from connection
		state: string &default="NULL" &log;	# action type
		orig_d: count &default=0 &log;		# orig data size field
		orig_d_trigger: count &default=0 &log;	# orig data size at trigger
		resp_d: count &default=0 &log;		# resp data size
		resp_d_trigger: count &default=0 &log;	# resp data size at trigger
		trigger: bool &default=F &log;		# has this connection record been triggered?
		clear: bool &default=F &log;		# has the connection shunt been cleared?
		id: conn_id &log;
		};

	global shunt_tracker: table[string] of count;	# identify pairs of o/r IP common to many flows

	const shunt_threshold =  179200000 &redef; # this is the shunt threshold
	const twoG = 2147483648;		#

	const initial_delay = 0.05 sec &redef;	# delay between S/SA/A and first peek
	const data_test_delay = .1 sec &redef;	# continuing delay between looking at conn sizes
	const cutoff_time = 30 sec &redef;	# end of measuring time window - if it takes more than 
						#  cutoff_time to get the shunt_threshold, we punt
	const shunt_track_high_water = 5 &redef; # if number flows w/ same o/r IP exceeds this, use common 
						#  pairs to dump all data for *new* flows
	const shunt_track_low_water = 2 &redef; # if count falls at or below this, stop adding new flows to IP track

	global get_key: function(a1: addr, a2: addr) : string;
	global log_shunt: event(rec: Info);

}
# add shunt info into the connection data type
redef record connection += {
	shunt_element:	Info  &optional;
};


event bro_init() &priority=5
        {
        Log::create_stream(Shunt::LOG, [$columns=Info, $ev=log_shunt]);
        }

function shunt_message(s: Info)
	{
	Log::write(Shunt::LOG, s);

	}

# the index for {IP,IP} flow monitoring is symmetric with regard 
#  to source and dest since the shunt deals with things that way.
#
function get_key(a1: addr, a2: addr) : string
	{
	local ret: string = "NONE";

	if ( a1 < a2 )
		ret = fmt("%s%s", a1, a2);
	else
		ret = fmt("%s%s", a2, a1);

	return ret;
	}

function print_cid(cid: conn_id): string
	{
	local rs: string = fmt("%s -> %s:%s", cid$orig_h, cid$resp_h, cid$resp_p);
	return rs;
	}


# This function tests the existance of the connection address pair in the 
#  flow blocker table.
#
function flow_tracker_test(c: connection): count
	{
	if ( ! c?$shunt_element )
		return 0;

	local oA: addr = c$id$orig_h;
	local rA: addr = c$id$resp_h;
	local ret: count = 0;
	local key = get_key(oA,rA);

	if ( key in shunt_tracker ) {

		if ( shunt_tracker[key] >= shunt_track_high_water )
			ret = 1;

		}
	return ret;
	}

# This function tracks the collective behavior of address pairs looking for 
#  opportunities for shunting address pairs rather than individual connections.
#
function flow_tracker_add(c: connection): count
	{

	if ( ! c?$shunt_element )
		return 0;

	local oA: addr = c$id$orig_h;
	local rA: addr = c$id$resp_h;
	local key = get_key(oA,rA);

	if ( key in shunt_tracker ) {

		# If the trigger time = 0.0, then we know that the data
		#  struct has not been filled in yet

		if ( c$shunt_element$pr_time != 0.0 ) {

			c$shunt_element$state = "ShuntTrackerIncrement";
			shunt_message(c$shunt_element);

			#NOTICE([$note=ShuntTrackerIncrement, $conn=c, 
			#	$msg=fmt("%.6f ShuntTracker increment %s -> %s [%s]", 
			#		network_time(), oA, rA, shunt_tracker[key])]);
			}

		if ( ++shunt_tracker[key] == shunt_track_high_water ) {

			c$shunt_element$state = "ShuntTrackerHighWater";
			shunt_message(c$shunt_element);

			#NOTICE([$note=ShuntTrackerHWater, $conn=c, 
			#	$msg=fmt("%.6f ShuntTracker high_water %s -> %s [%s]", 
			#		network_time(), oA, rA, shunt_tracker[key])]);
			}
		}
	else {

		c$shunt_element$state = "FlowTrackInit";
		shunt_message(c$shunt_element);

		shunt_tracker[key] = 1;
		}
	
	return shunt_tracker[key];
	} # end function

# Oposite to the above function - remove flow information at connection close
#
#  !! Add additional logic here to make sure we do not drift < 0
#
function flow_tracker_remove(c: connection): count
	{
	# if the connection does not exist, just return
	if ( ! c?$shunt_element )
		return 0;

	local oA: addr = c$id$orig_h;
	local rA: addr = c$id$resp_h;
	local ret_val = 0;
	local key = get_key(oA,rA);

	if ( key in shunt_tracker ) {

		if ( --shunt_tracker[key] == shunt_track_low_water ) {

			if ( c$shunt_element$pr_time != 0.0 ) {

				c$shunt_element$state = "ShuntTrackerLWater";
				shunt_message(c$shunt_element);

				#NOTICE([$note=ShuntTrackerLWater, $conn=c, 
				#	$msg=fmt("%.6f ShuntTracker low_water %s -> %s [%s]", 
				#		network_time(), oA, rA, shunt_tracker[key])]);
				}
		}

		ret_val = shunt_tracker[key];

		if ( shunt_tracker[key] == 0 ){
			delete shunt_tracker[key];

			c$shunt_element$state = "FlowTrackRemove";
			shunt_message(c$shunt_element);

			#print fmt("FlowTrack remove %s -> %s", oA, rA); # debug
			}
		}

	return ret_val;
	}


function clear_shunt(c: connection)
	{
	# The clear_shunt function takes a flow which has been slated for removal
	#   and dumps the performance informaiton if it is in a trigger == T state.
	#
	if ( ! c?$shunt_element )
		return;

	if ( c$shunt_element$clear == T )
		return;

	# only need to run the clear_shunt() function when both the conn has been
	#  triggered and the element state is not already "ShuntClear".
	#
	if ( c$shunt_element$trigger && c$shunt_element$state != "ShuntClear") {

		c$shunt_element$state = "ShuntClear";
		c$shunt_element$orig_d = c$orig$num_bytes_ip;
		c$shunt_element$resp_d = c$resp$num_bytes_ip;
		c$shunt_element$clear = T;

		shunt_message(c$shunt_element);

		local total_data = c$orig$num_bytes_ip + c$resp$num_bytes_ip;
		local total_trigger_data = c$shunt_element$orig_d_trigger +  c$shunt_element$resp_d_trigger;

		#print fmt("vlan and not ( host %s and host %s and port %s and port %s )", 
		#	c$id$orig_h, c$id$resp_h, port_to_count(c$id$orig_p), port_to_count(c$id$resp_p));

		local m = fmt("total d: %s trigger data: %s",
				total_data, total_trigger_data);

		NOTICE([$note=ShuntClear, $conn=c, 
			$msg=fmt("%.6f ShuntClear; %s bytes total; %s bytes %.2f sec skipped; %3f efficiency", 
				network_time(),
				total_data,
				total_data - total_trigger_data,
				time_to_double(network_time()) -  c$shunt_element$pr_time, 
				( (total_data - total_trigger_data) * 1.0) / ( total_data * 1.0)  )]);	
		}

	flow_tracker_remove(c);
	}

# Generic test for large data flows
#
event test_connection(c:connection)
	{
	# first see if the connection still exists ...
	if ( ! connection_exists(c$id) ) {

		c$shunt_element$state = "RemoveConnection";
		shunt_message(c$shunt_element);
		clear_shunt(c);
		return;
		}

	# then make sure that the shunt_element is stil in place
	if ( ! c?$shunt_element )
		return;

	# Cutoff_time test
	if ( (time_to_double(network_time()) - c$shunt_element$pr_time > interval_to_double(cutoff_time)) 
		&& c$shunt_element$trigger == F ) { 

			c$shunt_element$state = "CutoffTime";
			shunt_message(c$shunt_element);
			flow_tracker_remove(c);
			return;
			}

	# retest data transfer values
	c$shunt_element$orig_d = c$orig$num_bytes_ip;
	c$shunt_element$resp_d = c$resp$num_bytes_ip;

	c$shunt_element$state = "TestConnection";
	#shunt_message(c$shunt_element);

	# if the connection has not been triggered yet, take a look at the values
        if ( c$shunt_element$trigger == F )
                {
		local s_d =  c$orig$num_bytes_ip + c$resp$num_bytes_ip;
		local trigger_direction = "NULL";

		if ( c$orig$num_bytes_ip > shunt_threshold ) {
			trigger_direction = "ORIG";
			c$shunt_element$trigger == T;
			}

		if ( c$resp$num_bytes_ip > shunt_threshold ) {
			trigger_direction = "RESP";
			c$shunt_element$trigger == T;
			}

                if ( c$shunt_element$trigger == T )
                        {
			#print fmt("SHUNT TRIGGER %s @ %s", s_d, c$id);

			# data exceeds threshold mark
			c$shunt_element$state = "ShuntTrigger";
			c$shunt_element$pr_time = time_to_double(network_time());

			c$shunt_element$orig_d_trigger = c$orig$num_bytes_ip;
			c$shunt_element$orig_d = c$orig$num_bytes_ip;

			c$shunt_element$resp_d_trigger = c$resp$num_bytes_ip;
			c$shunt_element$resp_d = c$resp$num_bytes_ip;

			shunt_message(c$shunt_element);

			NOTICE([$note=ShuntTrigger, $conn=c, 
                        	$msg=fmt("%.6f ShuntTrigger %s %s ;%s bytes; %.2f sec; RATE: %.3f", 
					network_time(), trigger_direction, print_cid(c$id), s_d,
					time_to_double(network_time()) - c$shunt_element$pr_time, 
					(1.0 * s_d)/(interval_to_double(c$duration)+0.01) )]);
        
			# check with the flow tracker to see if the connection being looked at 
			#  has already been identified as an IP->IP high flow pair
			local fta = flow_tracker_add(c);

               		if (flow_tracker_add(c) >= shunt_track_high_water ) {

				c$shunt_element$state = "ShuntFlowIPIgnore";
				shunt_message(c$shunt_element);

				# This notice will be sent for all connection pairs 
				NOTICE([$note=ShuntFlowIPIgnore, $conn=c, 
					$msg=fmt("%.6f ShuntFlowIPIgnore %s -> %s",
						network_time(), c$id$orig_h, c$id$resp_h)]);

				#event ShuntQ::shunt_connection(c,"IP_PAIR",c$shunt_element$pr_time);
				Floodlight::shunt(c,"IP_PAIR",c$shunt_element$pr_time);
				
				}
			else {
				# code for inserting flow into shunt
				#event ShuntQ::shunt_connection(c,trigger_direction,c$shunt_element$pr_time);
				Floodlight::shunt(c,trigger_direction,c$shunt_element$pr_time);
				
				}
 
                        return;
                        } # end s_d > threshold block
			
			# if we are here then the connection has not triggered the shunt
			#  so reschedule another look
			schedule data_test_delay { test_connection(c) };
                } # trigger == F test

	# New test
	c$shunt_element$resp_d = c$resp$num_bytes_ip;
	c$shunt_element$orig_d = c$orig$num_bytes_ip;
	# end new test

        return;         
        }


event connection_established(c: connection)
	{
	local id: conn_id = c$id;

	if ( ! c?$shunt_element )
		{
		local s: Info;

		s$pr_time = time_to_double(network_time());
		s$orig_d = c$orig$size;
		s$resp_d = c$resp$size;
		s$index = c$uid;
		s$trigger = F;
		s$state = "ShuntFlowInit";
		s$id = c$id;

		c$shunt_element = s;

		shunt_message(c$shunt_element);
		}

	schedule initial_delay { test_connection(c) };
	}


event connection_finished(c: connection)
	{
	clear_shunt(c);
	}

event connection_rejected(c: connection)
	{
	clear_shunt(c);
	}

event connection_reset(c: connection)
	{
	clear_shunt(c);
	}

event connection_state_remove(c: connection) &priority = -10
	{
	clear_shunt(c);
	}

