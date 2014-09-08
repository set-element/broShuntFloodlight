broShuntingFramework
====================

The shunting framework uses a series of state transitions to define the behavior.  The various tranition states are:

  CutoffTime : Connections are analyzed for an observation period.  When that period expires 
      without adequate data being moved, then the session object is set to 'CutoffTime' and 
      the state removed.
  
  FlowTrackInit : A "FlowTrack" in this case is a pair of address' .  When a unique pair of 
      addresses is identified, the session state is set to FlowTrackInit to identify this.
  
  FlowTrackRemove : Like the Init above, when the last connection associated with an address 
      pair is closed, then the FlowTrack table entry is removed as well.
  
  RemoveConnection : If a connection no longer exists after the test_connection() function is 
      called, the state is set to RemoveConnection and the data is cleared via clear_shunt(c).
  
  ShuntClear : Something like the initial garbage collection call, this state signifies the start
      of the closing sequence called by flow_tracker_remove(c) .  
  
  ShuntFlowInit : When a connection is first seen at the connection_established event, the state is set
      to ShuntFlowInit and basic values are defined for the additonal connection structure.

  ShuntFlowIPIgnore : When flow_tracker_add(c) >= shunt_track_high_water the state is set to this to
      identify that the connection is being shunted via the more complete IP <-> IP filter.

  ShuntTrackerHighWater :  When ++shunt_tracker[oA,rA] == shunt_track_high_water and *this connection* pushes the 
      FlowTrack monitor over the threshold, then it's state will be set to ShuntTrackerHighWater.

  ShuntTrackerIncrement : This connection has incremented the pre-existing FlowTrack value. 

  ShuntTrackerLWater :  Likewise when --shunt_tracker[oA,rA] == shunt_track_low_water, this will get a connection
      state set to ShuntTrackerLWater.

  ShuntTrigger : A connection has exceeded the data volume requirements for shunting.

  TestConnection : This is more of a place holder in that the connection is still in testing.  There is 
      no reason for this to show up in the logs since it is consitered "normal".
  
  


