//SHA engine and bus probes (turbo_probe.cpp), built with -D NM_TURBO_PROBES
#pragma once
#ifdef NM_TURBO_PROBES
void turbo_probe_run();            //HW miner task, after turbo_hw_init()
const char *turbo_probe_json();    //"{...}" once run
#endif
