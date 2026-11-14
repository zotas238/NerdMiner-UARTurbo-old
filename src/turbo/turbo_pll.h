//Overclock: re-program the S3 BBPLL feedback divider at run time (see turbo_pll.cpp)
#pragma once
#include <stdint.h>

//PLL = 40 MHz * (div + 4); stock is div 8 (480 MHz, CPU 240). Returns true if the PLL
//reported lock; *us_out = time spent on the crystal while it relocked
//mode: bit 0 power-cycle + recalibrate the PLL (else rewrite the divider live), bit 1 use the flash guard
//(else stall the other core), bit 2 keep MSPI in high-speed mode
bool turbo_pll_set(uint8_t div, uint32_t *us_out, uint8_t mode = 0, uint8_t ref = 0);
uint8_t turbo_pll_get();
//Divider this boot started from, and the last one tried before a reset (RTC memory)
uint8_t turbo_pll_last_try();
void turbo_pll_boot();
//Locks the PLL at div and switches straight back to 8 without running on it (a dry run)
bool turbo_pll_dry(uint8_t div, uint32_t *us_out, uint8_t mode = 0, uint8_t ref = 0);
//Last switch: calibration ended, locked, fallback (1 = back on div 8, 2 = left on the crystal)
void turbo_pll_diag(uint32_t *cal, uint32_t *lock, uint32_t *fallback);
//Last switch stage reached before a reset (RTC memory), 0 = none
uint32_t turbo_pll_last_stage();
//ref divider in use, CPU MHz = 40 * (div + 4) / (ref + 1) / 2
uint8_t turbo_pll_ref();
uint32_t turbo_pll_mhz();
//core voltage code (I2C_DIG_REG reg 6 bits 4:0; IDF: 30 = 1.25 V, 31 = ~1.34 V): boot value, now, raw regs, set (capped)
uint8_t turbo_vdig_boot();
uint8_t turbo_vdig_get();
uint8_t turbo_vdig_reg(uint8_t r);
uint8_t turbo_vdig_set(uint8_t v);
//BBPLL analog registers now / at boot; extra settings applied on the next switch away from stock
uint8_t turbo_bb_reg(uint8_t r);
uint8_t turbo_bb_boot(uint8_t r);
int turbo_knob(uint8_t reg, uint8_t msb, uint8_t lsb, uint8_t val);
uint8_t turbo_pll_last_r8();
