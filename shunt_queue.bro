# impelementation of queue handler for the shunt policy
#
# [bro][shunt policy][queue mngr] -> application.py -> router
#                                 -> query.py -> router for acl list
#
# connection drops are done independant  of the ip <-> ip pair blocks so that 
#  the main blocks can be added or removed without changing any of the microstate
#
# when shunting [ip,ip] pairs, set the orig_p and resp_p to zero to identify pair 
#	shunting vs. connection shunting.
#
@load base/protocols/conn
@load base/utils/paths
@load base/utils/numbers
@load base/utils/addrs

module ShuntQ;

export {
	redef enum Notice::Type += {
		ShuntQueueAdd,
		ShuntQueueMalformed,
		ShuntQueueReplace,
		};

	type shunt_entity: record {
		ent_type: string &default="NULL"; # CONN, IP_PAIR etc...
		ent_count: count &default=0;	  # how many times the cid has been flagged
		ent_time: double &default=0.0;	  # timestamp for latest invocation
		ent_id: conn_id;		  #
		};

	# library of currently shunted connections
	global shunted_connections: table[conn_id] of shunt_entity;

	# queue of waiting shunts - index is "ent_type+low_ip+high_ip"
	global shunt_conn_queue: table[string] of shunt_entity &synchronized;
	global shunt_ippr_queue: table[string] of shunt_entity &synchronized;

	# the shunt_connection function is general in that the enttype can be CONNETION or IP_PAIR
	global shunt_connection: event(c: connection, enttype: string, dtime: double);
	global shunt_list: function() : count;

	## --- configuration data --- ##
	const batch_inserts = T &redef;
	const batch_interval = 10 sec &redef;
	const queue_min = 1 &redef;
	const queue_max = 1000 &redef;

	# time period (in sec) after which a entry is no longer
	#  consitered valid
	const stale_shunt_entry = 3600*24; # one day ..

	# lock to indentify when the run process is actively dropping things
	# this is done to avoid multiple logins to the shunt mechanism.
	bool SHUNT_LOCK = F &redef;
	}

### ----- Local Constants ----- ###
const SEP = "\n";
const ACL = "ip access-list extended shunt_list";
const DMPACL = " show ip access-list shunt_list";
const PTH = "deny tcp host ";
const EQ = " eq ";
const HST = " host ";
const EST = " established ";
const NO = " no ";

### ----- Functions ----- ###

# Operate on a connection to block a connection, IP pair or both
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

event shunt_connection(c: connection, enttype: string, dtime: double)
	{
	# here dtime is the shunt trigger time
	#
	#if ( Cluster::local_node_type() != Cluster::MANAGER )
	#	return;	

	# ret vals: 0: conn shunted, 1: shunt ignored, 2: malformed value
	local ret_val: count = 0;
	local t_se: shunt_entity;

	# hate to be cynical, but lets check a few things ...
	#if ( ! c?$shunt_element ) {
	#	ret_val = 2;
	#	return ret_val;
	#	}

	if ( dtime == 0.0 )
		dtime = time_to_double( network_time() );

	# generate the key value
	local s1 = get_key(c$id$orig_h, c$id$resp_h);
	local key: string = fmt("%s%s", s1, enttype);

	print fmt("SHUNTING: %s in quelen %s", key, |ShuntQ::shunt_conn_queue|);

	# For shunting an entire 2-sided connection
	if ( enttype == "CONN" ) {

		if ( key in ShuntQ::shunt_conn_queue )
			# shunt ignored ret val
			ret_val = 1;
		else {
			# add the value to the conn work queue	
			t_se$ent_type = enttype;
			t_se$ent_count = 1;
			t_se$ent_time = dtime; 
			t_se$ent_id = c$id;

			ShuntQ::shunt_conn_queue[key] = t_se;
			}
		
		} # end CONN

	# for addressing /any/ connections between two IPs
	if ( enttype == "IP_PAIR" ) {

		if ( key in shunt_ippr_queue )
			# shunt ignored ret val
			ret_val = 1;
		else {
			# add the value to the conn work queue	
			t_se$ent_type = enttype;
			t_se$ent_count = 1;
			t_se$ent_time = dtime; 
			t_se$ent_id = c$id;

			shunt_ippr_queue[key] = t_se;
			}
		
		} # end CONN
	
	# Begin flow based shunting	
	if ( enttype == "ORIG" ) {

	#return ret_val;
	return;
	}


### ----- Events ----- ###
event batch_run()
	{

	# we are already processing the list
	if ( SHUNT_LOCK ) {
		schedule batch_interval { batch_run() };
		return;
		}
	
	SHUNT_LOCK = T;
	
	local c_qlen = |ShuntQ::shunt_conn_queue|;
	local i_qlen = |ShuntQ::shunt_ippr_queue|;

	local block_string: string;

	#if ( c_qlen >= queue_min ) {

		local s_acl: string;
		local t_shunt_entity: shunt_entity;
		local shunt_st: string;

		print fmt("----- start conn queue dump -----");
		# run through the queue list and build the appropriate string
		for ( q in ShuntQ::shunt_conn_queue ) {
			local o = ShuntQ::shunt_conn_queue[q];
	
			shunt_st = fmt("%s %s %s %s %s %s %s %s %s", PTH, o$ent_id$orig_h, EQ,o$ent_id$orig_p, HST, o$ent_id$resp_h, EST, EQ, o$ent_id$resp_p);
			print shunt_st;
			delete ShuntQ::shunt_conn_queue[q];
			}
		print fmt("----- end conn queue dump -----");
	#	}

	SHUNT_LOCK = F;
	schedule batch_interval { batch_run() };
	}



event bro_init() &priority=5
        {
        if ( Cluster::local_node_type() == Cluster::PROXY ) {
		if ( ShuntQ::batch_inserts )
			schedule ShuntQ::batch_interval { batch_run() };
        	}
	}

