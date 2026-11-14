//BBPLL overclock for the wired build. Everything clocked from the PLL scales with it
//(CPU, APB, SHA engine, flash/PSRAM, USB, Wi-Fi); the wired build keeps Wi-Fi off and
//talks over UART0 clocked from the 40 MHz crystal, so only the CPU side matters.
//
//v2 (2026-11-03): v1 only rewrote the divider of the running PLL, and the board hung at the
//first step (div 9, interrupt WDT). This does what ESP-IDF's rtc_clk does when it changes the
//PLL frequency: MSPI (flash + PSRAM) into its low-speed mode first (its timing tuning is for
//exactly 80 MHz), CPU onto the crystal, PLL powered down and up so it calibrates again, every
//BBPLL analog register written as IDF writes them for 480 MHz except the divider, then wait
//for calibration end and lock before the CPU goes back on it. Returning to div 8 restores
//MSPI high-speed mode. If the new divider won't lock it goes back to 8; if that fails too it
//stays on the crystal (slow, but alive and still on the wire).
#include <Arduino.h>
#include <esp_attr.h>
#include <soc/system_reg.h>
#include <soc/rtc_cntl_reg.h>
#include <esp_spi_flash.h>
#include "turbo_pll.h"
#include <esp_cpu.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

extern "C" void rom_i2c_writeReg(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t data);
extern "C" uint8_t rom_i2c_readReg(uint8_t block, uint8_t host_id, uint8_t reg_add);
extern "C" void rom_i2c_writeReg_Mask(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t msb, uint8_t lsb, uint8_t data);
extern "C" uint8_t rom_i2c_readReg_Mask(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t msb, uint8_t lsb);
extern "C" void spi_timing_change_speed_mode_cache_safe(bool switch_down);

#define I2C_BBPLL 0x66
#define I2C_BBPLL_HOSTID 1
#define BBPLL_DIV_REG 3
#define PLL_MAGIC 0x504C4C21
// IDF values for 480 MHz from a 40 MHz crystal (rtc_clk_bbpll_configure, esp32s3)
#define BB_DIV_REF 0
#define BB_DCHGP 5
#define BB_DCUR 3
#define BB_DBIAS 2

RTC_NOINIT_ATTR static uint32_t s_pll_magic;
RTC_NOINIT_ATTR static uint32_t s_pll_try;
RTC_NOINIT_ATTR static volatile uint32_t s_stage;
static uint32_t s_last_stage = 0;
#define STAGE(n) (s_stage = (n))
static DRAM_ATTR volatile uint8_t s_div = 8;
static uint8_t s_last_try = 0;
static bool s_mspi_low = false;
static uint32_t s_last_cal = 0, s_last_lock = 0, s_last_fallback = 0;
static DRAM_ATTR uint8_t s_mode = 0;
static DRAM_ATTR uint8_t s_last_r8 = 0;   // reg 8 right after the last overclock attempt: lock 7, cal end 6, cal ovf 5, udf 4, cap 3:0
uint8_t turbo_pll_last_r8() { return s_last_r8; }
static DRAM_ATTR uint8_t s_ref = 0;        // BBPLL reference divider: VCO = 40 MHz * (div + 4) / (ref + 1)
static DRAM_ATTR uint8_t s_cur_ref = 0;
static DRAM_ATTR uint8_t s_boot_bb[16];    // BBPLL analog registers as the bootloader left them (stock 480 MHz)
struct knob_t { uint8_t reg, msb, lsb, val; };
static DRAM_ATTR knob_t s_knob[6];
static DRAM_ATTR volatile uint8_t s_nknob = 0;
static uint8_t s_boot_vdig = 0xff;
// the core voltage the chip came up with, kept across panic/software resets (which don't reset the
// regulator), so a raised value can't become the next boot's baseline
RTC_NOINIT_ATTR static uint32_t s_vdig_magic;
RTC_NOINIT_ATTR static uint32_t s_vdig_orig;
#define VDIG_MAGIC 0x56444947         // core voltage code (I2C_DIG_REG reg 6 bits 4:0) at boot
#define I2C_DIG_REG 0x6D
#define I2C_DIG_REG_HOSTID 1

void turbo_pll_boot()
{
  const uint8_t v_now = rom_i2c_readReg_Mask(I2C_DIG_REG, I2C_DIG_REG_HOSTID, 6, 4, 0);
  if (s_vdig_magic != VDIG_MAGIC || esp_reset_reason() == ESP_RST_POWERON || s_vdig_orig > 31)
  {
    s_vdig_magic = VDIG_MAGIC;
    s_vdig_orig = v_now;
  }
  s_boot_vdig = (uint8_t)s_vdig_orig;
  if (v_now != s_boot_vdig)
    rom_i2c_writeReg_Mask(I2C_DIG_REG, I2C_DIG_REG_HOSTID, 6, 4, 0, s_boot_vdig);
  for (int r = 0; r < 16; ++r) s_boot_bb[r] = rom_i2c_readReg(I2C_BBPLL, I2C_BBPLL_HOSTID, r);
  s_last_try = (s_pll_magic == PLL_MAGIC) ? (uint8_t)s_pll_try : 0;
  s_last_stage = (s_pll_magic == PLL_MAGIC) ? s_stage : 0;
  s_stage = 0;
  s_pll_magic = PLL_MAGIC;
  s_pll_try = 0;
  s_div = rom_i2c_readReg(I2C_BBPLL, I2C_BBPLL_HOSTID, BBPLL_DIV_REG);
}

uint8_t turbo_pll_get() { return s_div; }
uint8_t turbo_pll_last_try() { return s_last_try; }
uint32_t turbo_pll_last_stage() { return s_last_stage; }
void turbo_pll_diag(uint32_t *cal, uint32_t *lock, uint32_t *fallback)
{
  *cal = s_last_cal; *lock = s_last_lock; *fallback = s_last_fallback;
}

static inline uint32_t IRAM_ATTR ccount()
{
  uint32_t c;
  asm volatile("rsr %0, ccount" : "=a"(c));
  return c;
}

static inline void IRAM_ATTR spin(uint32_t cyc)
{
  const uint32_t t = ccount();
  while (ccount() - t < cyc) {}
}

//Powers the PLL down and up, programs it for divider div and waits (on the crystal, 40 MHz
//ccount) for calibration end and lock. Returns bit 0 = cal end, bit 1 = lock.
static uint32_t IRAM_ATTR bbpll_program(uint8_t div, uint32_t base)
{
  STAGE(base + 1);
  SET_PERI_REG_MASK(RTC_CNTL_OPTIONS0_REG, RTC_CNTL_BB_I2C_FORCE_PD | RTC_CNTL_BBPLL_FORCE_PD | RTC_CNTL_BBPLL_I2C_FORCE_PD);
  spin(400);   // 10 us
  STAGE(base + 2);
  CLEAR_PERI_REG_MASK(RTC_CNTL_OPTIONS0_REG, RTC_CNTL_BB_I2C_FORCE_PD | RTC_CNTL_BBPLL_FORCE_PD | RTC_CNTL_BBPLL_I2C_FORCE_PD);
  spin(400);
  STAGE(base + 3);
  // reg 2: dchgp + ref divider, ENB_FCAL (bit 7) clear = frequency calibration on
  rom_i2c_writeReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 2, (BB_DCHGP << 4) | BB_DIV_REF);
  rom_i2c_writeReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 3, div);
  rom_i2c_writeReg_Mask(I2C_BBPLL, I2C_BBPLL_HOSTID, 5, 2, 0, 0);   // DR1
  rom_i2c_writeReg_Mask(I2C_BBPLL, I2C_BBPLL_HOSTID, 5, 6, 4, 0);   // DR3
  rom_i2c_writeReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 6, (1 << 6) | (3 << 4) | BB_DCUR);   // DLREF_SEL, DHREF_SEL, DCUR
  rom_i2c_writeReg_Mask(I2C_BBPLL, I2C_BBPLL_HOSTID, 9, 1, 0, BB_DBIAS);   // VCO_DBIAS
  STAGE(base + 4);
  uint32_t r = 0;
  const uint32_t t0 = ccount();
  while (ccount() - t0 < 400000)   // 10 ms
  {
    const uint8_t s = rom_i2c_readReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 8);
    if ((s & 0x40) && (s & 0x80)) { r = 3; break; }
  }
  if (!r)
  {
    const uint8_t s = rom_i2c_readReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 8);
    r = ((s >> 6) & 1) | (((s >> 7) & 1) << 1);
  }
  STAGE(base + 5 + r * 1000);
  spin(8000);   // 200 us more to settle
  return r;
}

static uint32_t IRAM_ATTR bbpll_live(uint8_t div, uint32_t base)
{
  STAGE(base + 7);
  if (div == 8)
  {
    for (int r = 4; r <= 6; ++r) rom_i2c_writeReg(I2C_BBPLL, I2C_BBPLL_HOSTID, r, s_boot_bb[r]);
    rom_i2c_writeReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 1, s_boot_bb[1]);
    rom_i2c_writeReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 2, s_boot_bb[2]);
    s_cur_ref = s_boot_bb[2] & 0x0f;
  }
  else
    for (uint8_t k = 0; k < s_nknob; ++k)
      rom_i2c_writeReg_Mask(I2C_BBPLL, I2C_BBPLL_HOSTID, s_knob[k].reg, s_knob[k].msb, s_knob[k].lsb, s_knob[k].val);
  // bit 16: one step more VCO bias for the higher frequencies (stock 2), back to 2 at div 8
  rom_i2c_writeReg_Mask(I2C_BBPLL, I2C_BBPLL_HOSTID, 9, 1, 0, ((s_mode & 16) && div != 8) ? 3 : BB_DBIAS);
  const uint8_t ref = div == 8 ? 0 : s_ref;
  if (ref != s_cur_ref)
    rom_i2c_writeReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 2, (BB_DCHGP << 4) | ref);
  rom_i2c_writeReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 3, div);
  s_cur_ref = ref;
  if (s_mode & 8)
  {
    // restart the VCO frequency calibration: ENB_FCAL (reg 2 bit 7) up, then down
    rom_i2c_writeReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 2, (BB_DCHGP << 4) | ref | 0x80);
    spin(400);
    rom_i2c_writeReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 2, (BB_DCHGP << 4) | ref);
  }
  uint32_t r = 0;
  const uint32_t t0 = ccount();
  while (ccount() - t0 < 400000)
    if (rom_i2c_readReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 8) & 0x80) { r = 3; break; }
  if (div != 8) s_last_r8 = rom_i2c_readReg(I2C_BBPLL, I2C_BBPLL_HOSTID, 8);
  STAGE(base + 8 + r * 1000);
  spin(200000);   // 5 ms at 40 MHz: lock is reported before the loop has settled
  return r;
}
static inline uint32_t IRAM_ATTR program(uint8_t div, uint32_t base)
{
  return (s_mode & 1) ? bbpll_program(div, base) : bbpll_live(div, base);
}

//returns the status of the final programming; *fallback = 1 back on 8, 2 left on the crystal
static uint32_t IRAM_ATTR pll_switch(uint8_t div, bool dry, uint32_t *cyc, uint32_t *fallback)
{
  const uint32_t sys = REG_READ(SYSTEM_SYSCLK_CONF_REG);
  REG_WRITE(SYSTEM_SYSCLK_CONF_REG, sys & ~(SYSTEM_SOC_CLK_SEL_M | SYSTEM_PRE_DIV_CNT_M));   // CPU on the crystal
  const uint32_t t0 = ccount();
  STAGE(30);
  uint32_t st = program(div, 100);
  *fallback = 0;
  if (st != 3 || dry)
  {
    const uint32_t st8 = program(8, 200);
    if (st != 3) *fallback = st8 == 3 ? 1 : 2;
    if (st8 != 3) { *cyc = ccount() - t0; return st; }   // no PLL: stay on the crystal
    if (st != 3 || dry) div = 8;
  }
  *cyc = ccount() - t0;
  STAGE(40);
  if (s_mode & 32)
  {
    // onto the PLL at its slowest CPU divider first, then the real one
    const uint32_t per = REG_READ(SYSTEM_CPU_PER_CONF_REG);
    REG_WRITE(SYSTEM_CPU_PER_CONF_REG, per & ~SYSTEM_CPUPERIOD_SEL);
    spin(400);
    REG_WRITE(SYSTEM_SYSCLK_CONF_REG, sys);   // back on the PLL, CPU = PLL/6
    spin(20000);
    REG_WRITE(SYSTEM_CPU_PER_CONF_REG, per);   // CPU = PLL/2
    spin(20000);
  }
  else
    REG_WRITE(SYSTEM_SYSCLK_CONF_REG, sys);   // back on the PLL
  STAGE(41);
  s_div = div;
  return st;
}

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static bool turbo_pll_do(uint8_t div, bool dry, uint32_t *us_out, uint8_t mode, uint8_t ref)
{
  s_mode = mode;
  s_ref = ref;
  if (div < 4 || div > 40)
    return false;
  if (!dry)
    s_pll_try = div;   //survives a crash reset, so the next boot can report it
  STAGE(10);
  if (!s_mspi_low && !(mode & 4))
  {
    spi_timing_change_speed_mode_cache_safe(true);
    STAGE(11);
    s_mspi_low = true;
  }
  const spi_flash_guard_funcs_t *g = spi_flash_guard_get();
  uint32_t cyc = 0, fb = 0;
  uint32_t st;
  if (mode & 2)
  {
    STAGE(20);
    g->start();
    STAGE(21);
    st = pll_switch(div, dry, &cyc, &fb);
    STAGE(50);
    g->end();
    STAGE(51);
  }
  else
  {
    // no cooperative guard: interrupts off here, the other core stalled in hardware
    const int other = xPortGetCoreID() ^ 1;
    STAGE(22);
    portENTER_CRITICAL(&s_mux);
    esp_cpu_stall(other);
    STAGE(23);
    st = pll_switch(div, dry, &cyc, &fb);
    STAGE(52);
    esp_cpu_unstall(other);
    portEXIT_CRITICAL(&s_mux);
    STAGE(53);
  }
  (void)g;
  s_last_cal = st & 1; s_last_lock = (st >> 1) & 1; s_last_fallback = fb;
  if (s_div == 8 && fb != 2 && s_mspi_low)
  {
    spi_timing_change_speed_mode_cache_safe(false);
    s_mspi_low = false;
  }
  STAGE(60);
  if (us_out)
    *us_out = cyc / 40;
  if (s_div == 8)
    s_pll_try = 0;
  return st == 3;
}

bool turbo_pll_set(uint8_t div, uint32_t *us_out, uint8_t mode, uint8_t ref)
{
  const bool ok = turbo_pll_do(div, false, us_out, mode, ref);
  if (s_div == 8) turbo_vdig_set(s_boot_vdig);   // stock clock: stock voltage
  return ok;
}
bool turbo_pll_dry(uint8_t div, uint32_t *us_out, uint8_t mode, uint8_t ref) { return turbo_pll_do(div, true, us_out, mode, ref); }
uint8_t turbo_pll_ref() { return s_cur_ref; }
uint32_t turbo_pll_mhz() { return 40u * (s_div + 4) / (s_cur_ref + 1) / 2; }
uint8_t turbo_vdig_boot() { return s_boot_vdig; }
uint8_t turbo_bb_reg(uint8_t r) { return rom_i2c_readReg(I2C_BBPLL, I2C_BBPLL_HOSTID, r); }
uint8_t turbo_bb_boot(uint8_t r) { return r < 16 ? s_boot_bb[r] : 0; }
//K with reg 0xff clears; the knobs apply on the next switch away from div 8 (regs 2, 4-6 and 9 only)
int turbo_knob(uint8_t reg, uint8_t msb, uint8_t lsb, uint8_t val)
{
  if (reg == 0xff) { s_nknob = 0; return 0; }
  if (!(reg == 1 || reg == 2 || (reg >= 4 && reg <= 6) || reg == 9) || msb > 7 || lsb > msb || s_nknob >= 6) return -1;
  s_knob[s_nknob] = {reg, msb, lsb, val};
  return ++s_nknob;
}
uint8_t turbo_vdig_get() { return rom_i2c_readReg_Mask(I2C_DIG_REG, I2C_DIG_REG_HOSTID, 6, 4, 0); }
uint8_t turbo_vdig_reg(uint8_t r) { return rom_i2c_readReg(I2C_DIG_REG, I2C_DIG_REG_HOSTID, r); }
//Capped at 30 (1.25 V: IDF's own DIG_DBIAS_240M for chips without a calibrated value), never 31 (~1.34 V);
//returns the value now set
uint8_t turbo_vdig_set(uint8_t v)
{
  if (s_boot_vdig == 0xff) return turbo_vdig_get();
  uint8_t cap = s_boot_vdig > 30 ? s_boot_vdig : 30;
  if (v > cap) v = cap;
  rom_i2c_writeReg_Mask(I2C_DIG_REG, I2C_DIG_REG_HOSTID, 6, 4, 0, v);
  return turbo_vdig_get();
}
