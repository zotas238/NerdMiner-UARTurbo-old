//Turbo HW miner: the ESP32-S3 SHA engine driven directly (see turbo_hw.cpp)
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "../mining_job.h"

//Self-tests and picks the engine; call from the HW miner task before mining
void turbo_hw_init();
//Mines job into result (nonce_count = nonces done; stops early when cur_job changes)
void turbo_hw_job(const JobRequest &job, JobResult &result, volatile uint8_t &cur_job);
//"t4", "t1" or "stock"
const char *turbo_hw_mode_name();
//Status JSON fields (no braces) for the status port
int turbo_hw_status(char *buf, size_t len);
//Call once the board has run a while: resets the crash counter
void turbo_crash_guard_stable();

extern volatile uint32_t g_hw_hashes;
//Relay U: bus/split-burst benchmark, one line into buf (holds the SHA engine < 1 s)
int turbo_bus_bench(char *buf, size_t len);
int turbo_exp_bench(char *buf, size_t len);
int turbo_exp_bench_core0(char *buf, size_t len);
