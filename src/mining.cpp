#include <Arduino.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include <esp_task_wdt.h>
#include <esp_timer.h>
#include <nvs_flash.h>
#include <nvs.h>
//#include "ShaTests/nerdSHA256.h"
#include "ShaTests/nerdSHA256plus.h"
#include "stratum.h"
#include "mining.h"
#include "utils.h"
#include "monitor.h"
#include "timeconst.h"
#include "drivers/displays/display.h"
#include "drivers/storage/storage.h"
#include <mutex>
#include <list>
#include <map>
#include "mbedtls/sha256.h"
#include "i2c_master.h"
#include "mining_job.h"
#ifdef NM_TURBO
#include "turbo/turbo_hw.h"
#include "turbo/sha256_sw.h"
#include "turbo/turbo_probe.h"
#endif

//10 Jobs per second
#define NONCE_PER_JOB_SW 4096
#define NONCE_PER_JOB_HW 16*1024

#ifdef NM_TURBO
//Deeper HW queue so the HW miner never starves while stratum is busy
#define HW_QUEUE_DEPTH 8
//Hashes done by the SW miner (the HW count is in turbo_hw.cpp), for the status port
volatile uint32_t g_sw_hashes = 0;
//SW miner: variant in use (turbo/sha256_sw.cpp), cycles per nonce of each (0 = failed
//its known-answer test), 16-bit candidates checked, and those the reference disagreed with
volatile int g_sw_variant = -1;
volatile uint32_t g_asm_chk = 0xFFFFFFFF, g_asm_got = 0, g_asm_want = 0;
volatile uint32_t g_sw_cpn[TURBO_SW_VARIANTS] = {0};
volatile uint32_t g_sw_cands = 0;
volatile uint32_t g_sw_bad = 0;
//Diagnostics: stratum loop passes, times a miner found its queue empty
volatile uint32_t g_strat_loops = 0;
volatile uint32_t g_hw_starved = 0;
volatile uint32_t g_sw_starved = 0;
#else
#define HW_QUEUE_DEPTH 4
#endif

//#define I2C_SLAVE

//#define SHA256_VALIDATE
//#define RANDOM_NONCE
#define RANDOM_NONCE_MASK 0xFFFFC000

#ifdef HARDWARE_SHA265
#include <sha/sha_dma.h>
#include <hal/sha_hal.h>
#include <hal/sha_ll.h>

#if defined(CONFIG_IDF_TARGET_ESP32)
#include <sha/sha_parallel_engine.h>
#endif

#endif

nvs_handle_t stat_handle;

uint32_t templates = 0;
uint32_t hashes = 0;
uint32_t Mhashes = 0;
uint32_t totalKHashes = 0;
uint32_t elapsedKHs = 0;
uint64_t upTime = 0;

volatile uint32_t shares; // increase if blockhash has 32 bits of zeroes
volatile uint32_t valids; // increased if blockhash <= target

// Track best diff
double best_diff = 0.0;

// Variables to hold data from custom textboxes
//Track mining stats in non volatile memory
extern TSettings Settings;

IPAddress serverIP(1, 1, 1, 1); //Temporally save poolIPaddres

//Global work data 
static WiFiClient client;
static miner_data mMiner; //Global miner data (Create a miner class TODO)
mining_subscribe mWorker;
mining_job mJob;
monitor_data mMonitor;
static bool volatile isMinerSuscribed = false;
unsigned long mLastTXtoPool = millis();

int saveIntervals[7] = {5 * 60, 15 * 60, 30 * 60, 1 * 3600, 3 * 3600, 6 * 3600, 12 * 3600};
int saveIntervalsSize = sizeof(saveIntervals)/sizeof(saveIntervals[0]);
int currentIntervalIndex = 0;

bool checkPoolConnection(void) {
  
  if (client.connected()) {
    return true;
  }
  
  isMinerSuscribed = false;

  Serial.println("Client not connected, trying to connect..."); 
  
  //Resolve first time pool DNS and save IP
  if(serverIP == IPAddress(1,1,1,1)) {
    WiFi.hostByName(Settings.PoolAddress.c_str(), serverIP);
    Serial.printf("Resolved DNS and save ip (first time) got: %s\n", serverIP.toString());
  }

  //Try connecting pool IP
  if (!client.connect(serverIP, Settings.PoolPort)) {
    Serial.println("Imposible to connect to : " + Settings.PoolAddress);
    WiFi.hostByName(Settings.PoolAddress.c_str(), serverIP);
    Serial.printf("Resolved DNS got: %s\n", serverIP.toString());
    return false;
  }

  return true;
}

//Implements a socketKeepAlive function and 
//checks if pool is not sending any data to reconnect again.
//Even connection could be alive, pool could stop sending new job NOTIFY
unsigned long mStart0Hashrate = 0;
bool checkPoolInactivity(unsigned int keepAliveTime, unsigned long inactivityTime){ 

    unsigned long currentKHashes = (Mhashes*1000) + hashes/1000;
    unsigned long elapsedKHs = currentKHashes - totalKHashes;

    uint32_t time_now = millis();

    // If no shares sent to pool
    // send something to pool to hold socket oppened
    if (time_now < mLastTXtoPool) //32bit wrap
      mLastTXtoPool = time_now;
    if ( time_now > mLastTXtoPool + keepAliveTime)
    {
      mLastTXtoPool = time_now;
      Serial.println("  Sending  : KeepAlive suggest_difficulty");
      //if (client.print("{}\n") == 0) {
      tx_suggest_difficulty(client, DEFAULT_DIFFICULTY);
      /*if(tx_suggest_difficulty(client, DEFAULT_DIFFICULTY)){
        Serial.println("  Sending keepAlive to pool -> Detected client disconnected");
        return true;
      }*/
    }

    if(elapsedKHs == 0){
      //Check if hashrate is 0 during inactivityTIme
      if(mStart0Hashrate == 0) mStart0Hashrate  = time_now; 
      if((time_now-mStart0Hashrate) > inactivityTime) { mStart0Hashrate=0; return true;}
      return false;
    }

  mStart0Hashrate = 0;
  return false;
}

static std::mutex s_job_mutex;
std::list<std::shared_ptr<JobRequest>> s_job_request_list_sw;
#ifdef HARDWARE_SHA265
std::list<std::shared_ptr<JobRequest>> s_job_request_list_hw;
#endif
std::list<std::shared_ptr<JobResult>> s_job_result_list;
static volatile uint8_t s_working_current_job_id = 0xFF;

static void JobPush(std::list<std::shared_ptr<JobRequest>> &job_list,  uint32_t id, uint32_t nonce_start, uint32_t nonce_count, double difficulty,
                    const uint8_t* sha_buffer, const uint32_t* midstate, const uint32_t* bake)
{
  std::shared_ptr<JobRequest> job = std::make_shared<JobRequest>();
  job->id = id;
  job->nonce_start = nonce_start;
  job->nonce_count = nonce_count;
  job->difficulty = difficulty;
  memcpy(job->sha_buffer, sha_buffer, sizeof(job->sha_buffer));
  memcpy(job->midstate, midstate, sizeof(job->midstate));
  memcpy(job->bake, bake, sizeof(job->bake));
  job_list.push_back(job);
}

struct Submition
{
  double diff;
  bool is32bit;
  bool isValid;
};

static void MiningJobStop(uint32_t &job_pool, std::map<uint32_t, std::shared_ptr<Submition>> & submition_map)
{
  {
    std::lock_guard<std::mutex> lock(s_job_mutex);
    s_job_result_list.clear();
    s_job_request_list_sw.clear();
    #ifdef HARDWARE_SHA265
    s_job_request_list_hw.clear();
    #endif
  }
  s_working_current_job_id = 0xFF;
  job_pool = 0xFFFFFFFF;
  submition_map.clear();
}

#ifdef RANDOM_NONCE
uint64_t s_random_state = 1;
static uint32_t RandomGet()
{
    s_random_state += 0x9E3779B97F4A7C15ull;
    uint64_t z = s_random_state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

#endif

void runStratumWorker(void *name) {

// TEST: https://bitcoin.stackexchange.com/questions/22929/full-example-data-for-scrypt-stratum-client

  Serial.println("");
  Serial.printf("\n[WORKER] Started. Running %s on core %d\n", (char *)name, xPortGetCoreID());

  #ifdef DEBUG_MEMORY
  Serial.printf("### [Total Heap / Free heap / Min free heap]: %d / %d / %d \n", ESP.getHeapSize(), ESP.getFreeHeap(), ESP.getMinFreeHeap());
  #endif

  std::map<uint32_t, std::shared_ptr<Submition>> s_submition_map;

#ifdef I2C_SLAVE
  std::vector<uint8_t> i2c_slave_vector;

  //scan for i2c slaves
  if (i2c_master_start() == 0)
    i2c_slave_vector = i2c_master_scan(0x0, 0x80);
  Serial.printf("Found %d slave workers\n", i2c_slave_vector.size());
  if (!i2c_slave_vector.empty())
  {
    Serial.print("  Workers: ");
    for (size_t n = 0; n < i2c_slave_vector.size(); ++n)
      Serial.printf("0x%02X,", (uint32_t)i2c_slave_vector[n]);
    Serial.println("");
  }
#endif

  // connect to pool  
  double currentPoolDifficulty = DEFAULT_DIFFICULTY;
  uint32_t nonce_pool = 0;
  uint32_t job_pool = 0xFFFFFFFF;
  uint32_t last_job_time = millis();
  //Per-template data: written on mining.notify, read again by the refills on later
  //passes, so they must outlive one pass of the loop
  uint32_t hw_midstate[8];
  uint32_t diget_mid[8];
  uint32_t bake[32];
  #if defined(CONFIG_IDF_TARGET_ESP32)
  uint8_t sha_buffer_swap[128];
  #endif

  while(true) {
      
    if(WiFi.status() != WL_CONNECTED){
      // WiFi is disconnected, so reconnect now
      mMonitor.NerdStatus = NM_Connecting;
      MiningJobStop(job_pool, s_submition_map);
      WiFi.reconnect();
      vTaskDelay(5000 / portTICK_PERIOD_MS);
      continue;
    } 

    if(!checkPoolConnection()){
      //If server is not reachable add random delay for connection retries
      //Generate value between 1 and 60 secs
      MiningJobStop(job_pool, s_submition_map);
      vTaskDelay(((1 + rand() % 60) * 1000) / portTICK_PERIOD_MS);
      continue;
    }

    if(!isMinerSuscribed)
    {
      //Stop miner current jobs
      mWorker = init_mining_subscribe();

      // STEP 1: Pool server connection (SUBSCRIBE)
      if(!tx_mining_subscribe(client, mWorker)) { 
        client.stop();
        MiningJobStop(job_pool, s_submition_map);
        continue; 
      }
      
      strcpy(mWorker.wName, Settings.BtcWallet);
      strcpy(mWorker.wPass, Settings.PoolPassword);
      // STEP 2: Pool authorize work (Block Info)
      tx_mining_auth(client, mWorker.wName, mWorker.wPass); //Don't verifies authoritzation, TODO
      //tx_mining_auth2(client, mWorker.wName, mWorker.wPass); //Don't verifies authoritzation, TODO

      // STEP 3: Suggest pool difficulty
      tx_suggest_difficulty(client, currentPoolDifficulty);

      isMinerSuscribed=true;
      uint32_t time_now = millis();
      mLastTXtoPool = time_now;
      last_job_time = time_now;
    }

    //Check if pool is down for almost 5minutes and then restart connection with pool (1min=600000ms)
    if(checkPoolInactivity(KEEPALIVE_TIME_ms, POOLINACTIVITY_TIME_ms)){
      //Restart connection
      Serial.println("  Detected more than 2 min without data form stratum server. Closing socket and reopening...");
      client.stop();
      isMinerSuscribed=false;
      MiningJobStop(job_pool, s_submition_map);
      continue; 
    }

    {
      uint32_t time_now = millis();
      if (time_now < last_job_time) //32bit wrap
        last_job_time = time_now;
      if (time_now >= last_job_time + 10*60*1000)  //10minutes without job
      {
        client.stop();
        isMinerSuscribed=false;
        MiningJobStop(job_pool, s_submition_map);
        continue;
      }
    }

    //Read pending messages from pool
    while(client.connected() && client.available())
    {
      String line = client.readStringUntil('\n');
      //Serial.println("  Received message from pool");      
      stratum_method result = parse_mining_method(line);
      switch (result)
      {
          case MINING_NOTIFY:         if(parse_mining_notify(line, mJob))
                                      {
                                          {
                                            std::lock_guard<std::mutex> lock(s_job_mutex);
                                            s_job_request_list_sw.clear();
                                            #ifdef HARDWARE_SHA265
                                            s_job_request_list_hw.clear();
                                            #endif
                                          }
                                          //Increse templates readed
                                          templates++;
                                          job_pool++;
                                          s_working_current_job_id = job_pool & 0xFF; //Terminate current job in thread

                                          last_job_time = millis();
                                          mLastTXtoPool = last_job_time;

                                          uint32_t mh = hashes/1000000;
                                          Mhashes += mh;
                                          hashes -= mh*1000000;

                                          //Prepare data for new jobs
                                          mMiner=calculateMiningData(mWorker, mJob);

                                          memset(mMiner.bytearray_blockheader+80, 0, 128-80);
                                          mMiner.bytearray_blockheader[80] = 0x80;
                                          mMiner.bytearray_blockheader[126] = 0x02;
                                          mMiner.bytearray_blockheader[127] = 0x80;

                                          nerd_mids(diget_mid, mMiner.bytearray_blockheader);
                                          #ifdef NM_TURBO
                                          turbo_sw_bake(diget_mid, mMiner.bytearray_blockheader+64, bake);
                                          #else
                                          nerd_sha256_bake(diget_mid, mMiner.bytearray_blockheader+64, bake);
                                          #endif

                                          #ifdef HARDWARE_SHA265
                                          #if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)
                                            esp_sha_acquire_hardware();
                                            sha_hal_hash_block(SHA2_256,  mMiner.bytearray_blockheader, 64/4, true);
                                            sha_hal_read_digest(SHA2_256, hw_midstate);
                                            esp_sha_release_hardware();
                                          #endif
                                          #endif

                                          #if defined(CONFIG_IDF_TARGET_ESP32)
                                          for (int i = 0; i < 32; ++i)
                                            ((uint32_t*)sha_buffer_swap)[i] = __builtin_bswap32(((const uint32_t*)(mMiner.bytearray_blockheader))[i]);
                                          #endif

                                          #ifdef RANDOM_NONCE
                                          nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
                                          #else
                                            #ifdef I2C_SLAVE
                                            if (!i2c_slave_vector.empty())
                                              nonce_pool = 0x10000000;
                                            else
                                            #endif
                                              nonce_pool = 0xDA54E700;  //nonce 0x00000000 is not possible, start from some random nonce
                                          #endif
                                          

                                          {
                                            std::lock_guard<std::mutex> lock(s_job_mutex);
                                            for (int i = 0; i < 4; ++ i)
                                            {
                                              #if 1
                                              JobPush( s_job_request_list_sw, job_pool, nonce_pool, NONCE_PER_JOB_SW, currentPoolDifficulty, mMiner.bytearray_blockheader, diget_mid, bake);
                                              #ifdef RANDOM_NONCE
                                              nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
                                              #else
                                              nonce_pool += NONCE_PER_JOB_SW;
                                              #endif
                                              #endif
                                              #ifdef HARDWARE_SHA265
                                                #if defined(CONFIG_IDF_TARGET_ESP32)
                                                  JobPush( s_job_request_list_hw, job_pool, nonce_pool, NONCE_PER_JOB_HW, currentPoolDifficulty, sha_buffer_swap, hw_midstate, bake);
                                                #else
                                                  JobPush( s_job_request_list_hw, job_pool, nonce_pool, NONCE_PER_JOB_HW, currentPoolDifficulty, mMiner.bytearray_blockheader, hw_midstate, bake);
                                                #endif
                                              #ifdef RANDOM_NONCE
                                              nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
                                              #else
                                              nonce_pool += NONCE_PER_JOB_HW;
                                              #endif
                                              #endif
                                            }
                                          }
                                          #ifdef I2C_SLAVE
                                          //Nonce for nonce_pool starts from 0x10000000
                                          //For i2c slave we give nonces from 0x20000000, that is 0x10000000 nonces per slave
                                          i2c_feed_slaves(i2c_slave_vector, job_pool & 0xFF, 0x20, currentPoolDifficulty, mMiner.bytearray_blockheader);
                                          #endif
                                      } else
                                      {
                                        Serial.println("Parsing error, need restart");
                                        client.stop();
                                        isMinerSuscribed=false;
                                        MiningJobStop(job_pool, s_submition_map);
                                      }
                                      break;
          case MINING_SET_DIFFICULTY: parse_mining_set_difficulty(line, currentPoolDifficulty);
                                      break;
          case STRATUM_SUCCESS:       {
                                        unsigned long id = parse_extract_id(line);
                                        auto itt = s_submition_map.find(id);
                                        if (itt != s_submition_map.end())
                                        {
                                          if (itt->second->diff > best_diff)
                                            best_diff = itt->second->diff;
                                          if (itt->second->is32bit)
                                            shares++;
                                          if (itt->second->isValid)
                                          {
                                            Serial.println("CONGRATULATIONS! Valid block found");
                                            valids++;
                                          }
                                          s_submition_map.erase(itt);
                                        }
                                      }
                                      break;
          case STRATUM_PARSE_ERROR:   {
                                        unsigned long id = parse_extract_id(line);
                                        auto itt = s_submition_map.find(id);
                                        if (itt != s_submition_map.end())
                                        {
                                          Serial.printf("Refuse submition %d\n", id);
                                          s_submition_map.erase(itt);
                                        }
                                      }
                                      break;
          default:                    Serial.println("  Parsed JSON: unknown"); break;

      }
    }

    std::list<std::shared_ptr<JobResult>> job_result_list;
    #ifdef I2C_SLAVE
    if (i2c_slave_vector.empty() || job_pool == 0xFFFFFFFF)
    {
      vTaskDelay(50 / portTICK_PERIOD_MS); //Small delay
    } else
    {
      uint32_t time_start = millis();
      i2c_hit_slaves(i2c_slave_vector);
      vTaskDelay(5 / portTICK_PERIOD_MS);
      uint32_t nonces_done = 0;
      std::vector<uint32_t> nonce_vector = i2c_harvest_slaves(i2c_slave_vector, job_pool & 0xFF, nonces_done);
      hashes += nonces_done;
      for (size_t n = 0; n < nonce_vector.size(); ++n)
      {
        std::shared_ptr<JobResult> result = std::make_shared<JobResult>();
        ((uint32_t*)(mMiner.bytearray_blockheader+64+12))[0] = nonce_vector[n];
        if (nerd_sha256d_baked(diget_mid, mMiner.bytearray_blockheader+64, bake, result->hash))
        {
          result->id = job_pool;
          result->nonce = nonce_vector[n];
          result->nonce_count = 0;
          result->difficulty = diff_from_target(result->hash);
          job_result_list.push_back(result);
        }
      }
      uint32_t time_end = millis();
      //if (nonces_done > 16384)
        //Serial.printf("Harvest slaves in %dms hashes=%d\n", time_end - time_start, nonces_done);
      if (time_end > time_start)
      {
        uint32_t elapsed = time_end - time_start;
        if (elapsed < 50)
          vTaskDelay((50 - elapsed) / portTICK_PERIOD_MS);
      } else
        vTaskDelay(40 / portTICK_PERIOD_MS);
    }
    #else
    vTaskDelay(50 / portTICK_PERIOD_MS); //Small delay
    #endif
    #ifdef NM_TURBO
    g_strat_loops++;
    #endif

    
    if (job_pool != 0xFFFFFFFF)
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      job_result_list.insert(job_result_list.end(), s_job_result_list.begin(), s_job_result_list.end());
      s_job_result_list.clear();

#if 1
      while (s_job_request_list_sw.size() < 4)
      {
        JobPush( s_job_request_list_sw, job_pool, nonce_pool, NONCE_PER_JOB_SW, currentPoolDifficulty, mMiner.bytearray_blockheader, diget_mid, bake);
        #ifdef RANDOM_NONCE
        nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
        #else
        nonce_pool += NONCE_PER_JOB_SW;
        #endif
      }
#endif

      #ifdef HARDWARE_SHA265
      while (s_job_request_list_hw.size() < HW_QUEUE_DEPTH)
      {
        #if defined(CONFIG_IDF_TARGET_ESP32)
          JobPush( s_job_request_list_hw, job_pool, nonce_pool, NONCE_PER_JOB_HW, currentPoolDifficulty, sha_buffer_swap, hw_midstate, bake);
        #else
          JobPush( s_job_request_list_hw, job_pool, nonce_pool, NONCE_PER_JOB_HW, currentPoolDifficulty, mMiner.bytearray_blockheader, hw_midstate, bake);
        #endif
        #ifdef RANDOM_NONCE
        nonce_pool = RandomGet() & RANDOM_NONCE_MASK;
        #else
        nonce_pool += NONCE_PER_JOB_HW;
        #endif
      }
      #endif
    }

    while (!job_result_list.empty())
    {
      std::shared_ptr<JobResult> res = job_result_list.front();
      job_result_list.pop_front();

      hashes += res->nonce_count;
      if (res->difficulty > currentPoolDifficulty && job_pool == res->id && res->nonce != 0xFFFFFFFF)
      {
        if (!client.connected())
          break;
        unsigned long sumbit_id = 0;
        tx_mining_submit(client, mWorker, mJob, res->nonce, sumbit_id);
        #ifndef NM_TURBO
        Serial.print("   - Current diff share: "); Serial.println(res->difficulty,12);
        Serial.print("   - Current pool diff : "); Serial.println(currentPoolDifficulty,12);
        Serial.print("   - TX SHARE: ");
        for (size_t i = 0; i < 32; i++)
            Serial.printf("%02x", res->hash[i]);
        Serial.println("");
        #endif
        mLastTXtoPool = millis();

        std::shared_ptr<Submition> submition = std::make_shared<Submition>();
        submition->diff = res->difficulty;
        submition->is32bit = (res->hash[29] == 0 && res->hash[28] == 0);
        if (submition->is32bit)
        {
          submition->isValid = checkValid(res->hash, mMiner.bytearray_target);
        } else
          submition->isValid = false;

        s_submition_map.insert(std::make_pair(sumbit_id, submition));
        if (s_submition_map.size() > 32)
          s_submition_map.erase(s_submition_map.begin());
      }
    }
  }
}

//////////////////THREAD CALLS///////////////////

#ifdef NM_TURBO
//Picks the fastest SW double-SHA variant (turbo/sha256_sw.cpp) that passes its
//known-answer test, timed on this core
static void turbo_sw_pick()
{
  uint8_t hdr[80];
  for (int i = 0; i < 80; ++i)
    hdr[i] = (uint8_t)(i * 29 + 5);
  uint32_t mid[8], bake[TURBO_SW_BAKE_WORDS];
  nerd_mids(mid, hdr);
  turbo_sw_bake(mid, hdr + 64, bake);
  uint8_t hash[32];
  int best = -1;
  for (int v = 0; v < TURBO_SW_VARIANTS; ++v)
  {
    const TurboSwFn fn = turbo_sw_variants[v].fn;
    if (!turbo_sw_selftest(fn))
      continue;
    uint32_t cpn = 0xFFFFFFFF;
    for (int r = 0; r < 3; ++r)
    {
      const int64_t t0 = esp_timer_get_time();
      for (uint32_t n = 0; n < 1024; ++n)
        fn(bake, n, hash);
      const uint32_t c = (uint32_t)((esp_timer_get_time() - t0) * 240 / 1024);
      if (c < cpn) cpn = c;
    }
    g_sw_cpn[v] = cpn;
    if (best < 0 || cpn < g_sw_cpn[best])
      best = v;
  }
  g_asm_chk = turbo_sw_asm_check(64, (uint32_t *)&g_asm_got, (uint32_t *)&g_asm_want);
  if (best >= 0)
    turbo_sw_hash = turbo_sw_variants[best].fn;
  g_sw_variant = best;
  Serial.printf("[MINER] SW sha256d %s: %u / %u / %u / %u cycles per nonce\n", best >= 0 ? turbo_sw_variants[best].name : "none",
                (unsigned)g_sw_cpn[0], (unsigned)g_sw_cpn[1], (unsigned)g_sw_cpn[2], (unsigned)g_sw_cpn[3]);
}
#endif

void minerWorkerSw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerSw Task!\n", miner_id);

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint8_t hash[32];
  uint32_t wdt_counter = 0;
  #ifdef NM_TURBO
  turbo_sw_pick();
  #endif
  while (1)
  {
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (result)
      {
        if (s_job_result_list.size() < 16)
          s_job_result_list.push_back(result);
        result.reset();
      }
      if (!s_job_request_list_sw.empty())
      {
        job = s_job_request_list_sw.front();
        s_job_request_list_sw.pop_front();
      } else
        job.reset();
    }
    if (job)
    {
      result = std::make_shared<JobResult>();
      result->difficulty = job->difficulty;
      result->nonce = 0xFFFFFFFF;
      result->id = job->id;
      result->nonce_count = job->nonce_count;
      uint8_t job_in_work = job->id & 0xFF;
      #ifdef NM_TURBO
      const TurboSwFn sw_hash = turbo_sw_hash;
      #endif
      for (uint32_t n = 0; n < job->nonce_count; ++n)
      {
        #ifdef NM_TURBO
        if (sw_hash(job->bake, job->nonce_start + n, hash))
        {
          //checked against the independent reference before it can become a share
          g_sw_cands++;
          if (!turbo_ref_check(job->sha_buffer, job->nonce_start + n, hash))
          {
            g_sw_bad++;
            continue;
          }
        #else
        ((uint32_t*)(job->sha_buffer+64+12))[0] = job->nonce_start+n;
        if (nerd_sha256d_baked(job->midstate, job->sha_buffer+64, job->bake, hash))
        {
        #endif
          double diff_hash = diff_from_target(hash);
          if (diff_hash > result->difficulty)
          {
            result->difficulty = diff_hash;
            result->nonce = job->nonce_start+n;
            memcpy(result->hash, hash, 32);
          }
        }

        if ( (uint16_t)(n & 0xFF) == 0 &&s_working_current_job_id != job_in_work)
        {
          result->nonce_count = n+1;
          break;
        }
      }
      #ifdef NM_TURBO
      g_sw_hashes += result->nonce_count;
      #endif
    } else
    {
      #ifdef NM_TURBO
      g_sw_starved++;
      #endif
      vTaskDelay(2 / portTICK_PERIOD_MS);
    }

    wdt_counter++;
    if (wdt_counter >= 8)
    {
      wdt_counter = 0;
      esp_task_wdt_reset();
    }
  }
}

#ifdef HARDWARE_SHA265

#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)

static inline void nerd_sha_ll_fill_text_block_sha256(const void *input_text, uint32_t nonce)
{
    uint32_t *data_words = (uint32_t *)input_text;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

    REG_WRITE(&reg_addr_buf[0], data_words[0]);
    REG_WRITE(&reg_addr_buf[1], data_words[1]);
    REG_WRITE(&reg_addr_buf[2], data_words[2]);
#if 0
    REG_WRITE(&reg_addr_buf[3], nonce);
    //REG_WRITE(&reg_addr_buf[3], data_words[3]);    
    REG_WRITE(&reg_addr_buf[4], data_words[4]);
    REG_WRITE(&reg_addr_buf[5], data_words[5]);
    REG_WRITE(&reg_addr_buf[6], data_words[6]);
    REG_WRITE(&reg_addr_buf[7], data_words[7]);
    REG_WRITE(&reg_addr_buf[8], data_words[8]);
    REG_WRITE(&reg_addr_buf[9], data_words[9]);
    REG_WRITE(&reg_addr_buf[10], data_words[10]);
    REG_WRITE(&reg_addr_buf[11], data_words[11]);
    REG_WRITE(&reg_addr_buf[12], data_words[12]);
    REG_WRITE(&reg_addr_buf[13], data_words[13]);
    REG_WRITE(&reg_addr_buf[14], data_words[14]);
    REG_WRITE(&reg_addr_buf[15], data_words[15]);
#else
    REG_WRITE(&reg_addr_buf[3], nonce);
    REG_WRITE(&reg_addr_buf[4], 0x00000080);
    REG_WRITE(&reg_addr_buf[5], 0x00000000);
    REG_WRITE(&reg_addr_buf[6], 0x00000000);
    REG_WRITE(&reg_addr_buf[7], 0x00000000);
    REG_WRITE(&reg_addr_buf[8], 0x00000000);
    REG_WRITE(&reg_addr_buf[9], 0x00000000);
    REG_WRITE(&reg_addr_buf[10], 0x00000000);
    REG_WRITE(&reg_addr_buf[11], 0x00000000);
    REG_WRITE(&reg_addr_buf[12], 0x00000000);
    REG_WRITE(&reg_addr_buf[13], 0x00000000);
    REG_WRITE(&reg_addr_buf[14], 0x00000000);
    REG_WRITE(&reg_addr_buf[15], 0x80020000);
#endif
}

static inline void nerd_sha_ll_fill_text_block_sha256_inter()
{
  uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

  DPORT_INTERRUPT_DISABLE();
  REG_WRITE(&reg_addr_buf[0], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 0 * 4));
  REG_WRITE(&reg_addr_buf[1], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 1 * 4));
  REG_WRITE(&reg_addr_buf[2], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 2 * 4));
  REG_WRITE(&reg_addr_buf[3], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 3 * 4));
  REG_WRITE(&reg_addr_buf[4], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 4 * 4));
  REG_WRITE(&reg_addr_buf[5], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 5 * 4));
  REG_WRITE(&reg_addr_buf[6], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 6 * 4));
  REG_WRITE(&reg_addr_buf[7], DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 7 * 4));
  DPORT_INTERRUPT_RESTORE();

  REG_WRITE(&reg_addr_buf[8], 0x00000080);
  REG_WRITE(&reg_addr_buf[9], 0x00000000);
  REG_WRITE(&reg_addr_buf[10], 0x00000000);
  REG_WRITE(&reg_addr_buf[11], 0x00000000);
  REG_WRITE(&reg_addr_buf[12], 0x00000000);
  REG_WRITE(&reg_addr_buf[13], 0x00000000);
  REG_WRITE(&reg_addr_buf[14], 0x00000000);
  REG_WRITE(&reg_addr_buf[15], 0x00010000);
}

static inline void nerd_sha_ll_read_digest(void* ptr)
{
  DPORT_INTERRUPT_DISABLE();
  ((uint32_t*)ptr)[0] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 0 * 4);
  ((uint32_t*)ptr)[1] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 1 * 4);
  ((uint32_t*)ptr)[2] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 2 * 4);
  ((uint32_t*)ptr)[3] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 3 * 4);
  ((uint32_t*)ptr)[4] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 4 * 4);
  ((uint32_t*)ptr)[5] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 5 * 4);
  ((uint32_t*)ptr)[6] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 6 * 4);  
  ((uint32_t*)ptr)[7] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 7 * 4);
  DPORT_INTERRUPT_RESTORE();
}


static inline bool nerd_sha_ll_read_digest_if(void* ptr)
{
  DPORT_INTERRUPT_DISABLE();
  uint32_t last = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 7 * 4);
  #if 1
  if ( (uint16_t)(last >> 16) != 0)
  {
    DPORT_INTERRUPT_RESTORE();
    return false;
  }
  #endif

  ((uint32_t*)ptr)[7] = last;
  ((uint32_t*)ptr)[0] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 0 * 4);
  ((uint32_t*)ptr)[1] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 1 * 4);
  ((uint32_t*)ptr)[2] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 2 * 4);
  ((uint32_t*)ptr)[3] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 3 * 4);
  ((uint32_t*)ptr)[4] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 4 * 4);
  ((uint32_t*)ptr)[5] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 5 * 4);
  ((uint32_t*)ptr)[6] = DPORT_SEQUENCE_REG_READ(SHA_H_BASE + 6 * 4);  
  DPORT_INTERRUPT_RESTORE();
  return true;
}

static inline void nerd_sha_ll_write_digest(void *digest_state)
{
    uint32_t *digest_state_words = (uint32_t *)digest_state;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_H_BASE);

    REG_WRITE(&reg_addr_buf[0], digest_state_words[0]);
    REG_WRITE(&reg_addr_buf[1], digest_state_words[1]);
    REG_WRITE(&reg_addr_buf[2], digest_state_words[2]);
    REG_WRITE(&reg_addr_buf[3], digest_state_words[3]);
    REG_WRITE(&reg_addr_buf[4], digest_state_words[4]);
    REG_WRITE(&reg_addr_buf[5], digest_state_words[5]);
    REG_WRITE(&reg_addr_buf[6], digest_state_words[6]);
    REG_WRITE(&reg_addr_buf[7], digest_state_words[7]);
}

static inline void nerd_sha_hal_wait_idle()
{
    while (REG_READ(SHA_BUSY_REG))
    {}
}

#ifdef NM_TURBO

//The turbo engine lives in turbo/turbo_hw.cpp; this task only moves jobs and results
void minerWorkerHw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started turbo minerWorkerHw Task on core %d!\n", miner_id, xPortGetCoreID());
  turbo_hw_init();
  #ifdef NM_TURBO_PROBES
  turbo_probe_run();
  #endif

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint32_t wdt_counter = 0;

  while (1)
  {
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (result)
      {
        if (s_job_result_list.size() < 16)
          s_job_result_list.push_back(result);
        result.reset();
      }
      if (!s_job_request_list_hw.empty())
      {
        job = s_job_request_list_hw.front();
        s_job_request_list_hw.pop_front();
      } else
        job.reset();
    }
    if (job)
    {
      result = std::make_shared<JobResult>();
      result->id = job->id;
      result->nonce = 0xFFFFFFFF;
      result->difficulty = job->difficulty;
      turbo_hw_job(*job, *result, s_working_current_job_id);
      g_hw_hashes += result->nonce_count;
    } else
    {
      g_hw_starved++;
      vTaskDelay(2 / portTICK_PERIOD_MS);
    }

    wdt_counter++;
    if (wdt_counter >= 8)
    {
      wdt_counter = 0;
      esp_task_wdt_reset();
    }
  }
}

#else

//#define VALIDATION
void minerWorkerHw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerHw Task!\n", miner_id);

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint8_t interResult[64];
  uint8_t hash[32];
  uint8_t digest_mid[32];
  uint8_t sha_buffer[64];
  uint32_t wdt_counter = 0;

#ifdef VALIDATION
  uint8_t doubleHash[32];
  uint32_t diget_mid[8];
  uint32_t bake[16];
#endif

  while (1)
  {
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (result)
      {
        if (s_job_result_list.size() < 16)
          s_job_result_list.push_back(result);
        result.reset();
      }
      if (!s_job_request_list_hw.empty())
      {
        job = s_job_request_list_hw.front();
        s_job_request_list_hw.pop_front();
      } else
        job.reset();
    }
    if (job)
    {
      result = std::make_shared<JobResult>();
      result->id = job->id;
      result->nonce = 0xFFFFFFFF;
      result->nonce_count = job->nonce_count;
      result->difficulty = job->difficulty;
      uint8_t job_in_work = job->id & 0xFF;
      memcpy(digest_mid, job->midstate, sizeof(digest_mid));
      memcpy(sha_buffer, job->sha_buffer+64, sizeof(sha_buffer));
#ifdef VALIDATION
      nerd_mids(diget_mid, job->sha_buffer);
      nerd_sha256_bake(diget_mid, job->sha_buffer+64, bake);
#endif

      esp_sha_acquire_hardware();
      REG_WRITE(SHA_MODE_REG, SHA2_256);
      uint32_t nend = job->nonce_start + job->nonce_count;
      for (uint32_t n = job->nonce_start; n < nend; ++n)
      {
        //nerd_sha_hal_wait_idle();
        nerd_sha_ll_write_digest(digest_mid);
        //nerd_sha_hal_wait_idle();
        nerd_sha_ll_fill_text_block_sha256(sha_buffer, n);
        //sha_ll_continue_block(SHA2_256);
        REG_WRITE(SHA_CONTINUE_REG, 1);
        
        sha_ll_load(SHA2_256);
        nerd_sha_hal_wait_idle();
        nerd_sha_ll_fill_text_block_sha256_inter();
        //sha_ll_start_block(SHA2_256);
        REG_WRITE(SHA_START_REG, 1);
        sha_ll_load(SHA2_256);
        nerd_sha_hal_wait_idle();
        if (nerd_sha_ll_read_digest_if(hash))
        {
          //Serial.printf("Hw 16bit Share, nonce=0x%X\n", n);
#ifdef VALIDATION
          //Validation
          ((uint32_t*)(job->sha_buffer+64+12))[0] = n;
          nerd_sha256d_baked(diget_mid, job->sha_buffer+64, bake, doubleHash);
          for (int i = 0; i < 32; ++i)
          {
            if (hash[i] != doubleHash[i])
            {
              Serial.println("***HW sha256 esp32s3 bug detected***");
              break;
            }
          }
#endif
          //~5 per second
          double diff_hash = diff_from_target(hash);
          if (diff_hash > result->difficulty)
          {
            if (isSha256Valid(hash))
            {
              result->difficulty = diff_hash;
              result->nonce = n;
              memcpy(result->hash, hash, sizeof(hash));
            }
          }
        }
        if (
             (uint8_t)(n & 0xFF) == 0 &&
             s_working_current_job_id != job_in_work)
        {
          result->nonce_count = n-job->nonce_start+1;
          break;
        }
      }
      esp_sha_release_hardware();
    } else
      vTaskDelay(2 / portTICK_PERIOD_MS);

    wdt_counter++;
    if (wdt_counter >= 8)
    {
      wdt_counter = 0;
      esp_task_wdt_reset();
    }
  }
}

#endif  //NM_TURBO

#endif  //#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)

#if defined(CONFIG_IDF_TARGET_ESP32)

static inline bool nerd_sha_ll_read_digest_swap_if(void* ptr)
{
  DPORT_INTERRUPT_DISABLE();
  uint32_t fin = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 7 * 4);
  if ( (uint32_t)(fin & 0xFFFF) != 0)
  {
    DPORT_INTERRUPT_RESTORE();
    return false;
  }
  ((uint32_t*)ptr)[7] = __builtin_bswap32(fin);
  ((uint32_t*)ptr)[0] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 0 * 4));
  ((uint32_t*)ptr)[1] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 1 * 4));
  ((uint32_t*)ptr)[2] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 2 * 4));
  ((uint32_t*)ptr)[3] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 3 * 4));
  ((uint32_t*)ptr)[4] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 4 * 4));
  ((uint32_t*)ptr)[5] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 5 * 4));
  ((uint32_t*)ptr)[6] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 6 * 4));
  DPORT_INTERRUPT_RESTORE();
  return true;
}

static inline void nerd_sha_ll_read_digest(void* ptr)
{
  DPORT_INTERRUPT_DISABLE();
  ((uint32_t*)ptr)[0] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 0 * 4);
  ((uint32_t*)ptr)[1] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 1 * 4);
  ((uint32_t*)ptr)[2] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 2 * 4);
  ((uint32_t*)ptr)[3] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 3 * 4);
  ((uint32_t*)ptr)[4] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 4 * 4);
  ((uint32_t*)ptr)[5] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 5 * 4);
  ((uint32_t*)ptr)[6] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 6 * 4);
  ((uint32_t*)ptr)[7] = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 7 * 4);
  DPORT_INTERRUPT_RESTORE();
}

static inline void nerd_sha_hal_wait_idle()
{
    while (DPORT_REG_READ(SHA_256_BUSY_REG))
    {}
}

static inline void nerd_sha_ll_fill_text_block_sha256(const void *input_text)
{
    uint32_t *data_words = (uint32_t *)input_text;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = data_words[3];
    reg_addr_buf[4]  = data_words[4];
    reg_addr_buf[5]  = data_words[5];
    reg_addr_buf[6]  = data_words[6];
    reg_addr_buf[7]  = data_words[7];
    reg_addr_buf[8]  = data_words[8];
    reg_addr_buf[9]  = data_words[9];
    reg_addr_buf[10] = data_words[10];
    reg_addr_buf[11] = data_words[11];
    reg_addr_buf[12] = data_words[12];
    reg_addr_buf[13] = data_words[13];
    reg_addr_buf[14] = data_words[14];
    reg_addr_buf[15] = data_words[15];
}

static inline void nerd_sha_ll_fill_text_block_sha256_upper(const void *input_text, uint32_t nonce)
{
    uint32_t *data_words = (uint32_t *)input_text;
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = __builtin_bswap32(nonce);
#if 1
    reg_addr_buf[4]  = 0x80000000;
    reg_addr_buf[5]  = 0x00000000;
    reg_addr_buf[6]  = 0x00000000;
    reg_addr_buf[7]  = 0x00000000;
    reg_addr_buf[8]  = 0x00000000;
    reg_addr_buf[9]  = 0x00000000;
    reg_addr_buf[10] = 0x00000000;
    reg_addr_buf[11] = 0x00000000;
    reg_addr_buf[12] = 0x00000000;
    reg_addr_buf[13] = 0x00000000;
    reg_addr_buf[14] = 0x00000000;
    reg_addr_buf[15] = 0x00000280;
#else
    reg_addr_buf[4]  = data_words[4];
    reg_addr_buf[5]  = data_words[5];
    reg_addr_buf[6]  = data_words[6];
    reg_addr_buf[7]  = data_words[7];
    reg_addr_buf[8]  = data_words[8];
    reg_addr_buf[9]  = data_words[9];
    reg_addr_buf[10] = data_words[10];
    reg_addr_buf[11] = data_words[11];
    reg_addr_buf[12] = data_words[12];
    reg_addr_buf[13] = data_words[13];
    reg_addr_buf[14] = data_words[14];
    reg_addr_buf[15] = data_words[15];
#endif
}

static inline void nerd_sha_ll_fill_text_block_sha256_double()
{
    uint32_t *reg_addr_buf = (uint32_t *)(SHA_TEXT_BASE);

#if 0
    //No change
    reg_addr_buf[0]  = data_words[0];
    reg_addr_buf[1]  = data_words[1];
    reg_addr_buf[2]  = data_words[2];
    reg_addr_buf[3]  = data_words[3];
    reg_addr_buf[4]  = data_words[4];
    reg_addr_buf[5]  = data_words[5];
    reg_addr_buf[6]  = data_words[6];
    reg_addr_buf[7]  = data_words[7];
#endif
    reg_addr_buf[8]  = 0x80000000;
    reg_addr_buf[9]  = 0x00000000;
    reg_addr_buf[10] = 0x00000000;
    reg_addr_buf[11] = 0x00000000;
    reg_addr_buf[12] = 0x00000000;
    reg_addr_buf[13] = 0x00000000;
    reg_addr_buf[14] = 0x00000000;
    reg_addr_buf[15] = 0x00000100;
}

void minerWorkerHw(void * task_id)
{
  unsigned int miner_id = (uint32_t)task_id;
  Serial.printf("[MINER] %d Started minerWorkerHwEsp32D Task!\n", miner_id);

  std::shared_ptr<JobRequest> job;
  std::shared_ptr<JobResult> result;
  uint8_t hash[32];
  uint8_t sha_buffer[128];

  while (1)
  {
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      if (result)
      {
        if (s_job_result_list.size() < 16)
          s_job_result_list.push_back(result);
        result.reset();
      }
      if (!s_job_request_list_hw.empty())
      {
        job = s_job_request_list_hw.front();
        s_job_request_list_hw.pop_front();
      } else
        job.reset();
    }
    if (job)
    {
      result = std::make_shared<JobResult>();
      result->id = job->id;
      result->nonce = 0xFFFFFFFF;
      result->nonce_count = job->nonce_count;
      result->difficulty = job->difficulty;
      uint8_t job_in_work = job->id & 0xFF;
      memcpy(sha_buffer, job->sha_buffer, 80);

      esp_sha_lock_engine(SHA2_256);
      for (uint32_t n = 0; n < job->nonce_count; ++n)
      {
        //((uint32_t*)(sha_buffer+64+12))[0] = __builtin_bswap32(job->nonce_start+n);

        //sha_hal_hash_block(SHA2_256, s_test_buffer, 64/4, true);
        //nerd_sha_hal_wait_idle();
        nerd_sha_ll_fill_text_block_sha256(sha_buffer);
        sha_ll_start_block(SHA2_256);

        //sha_hal_hash_block(SHA2_256, s_test_buffer+64, 64/4, false);
        nerd_sha_hal_wait_idle();
        nerd_sha_ll_fill_text_block_sha256_upper(sha_buffer+64, job->nonce_start+n);
        sha_ll_continue_block(SHA2_256);

        nerd_sha_hal_wait_idle();
        sha_ll_load(SHA2_256);

        //sha_hal_hash_block(SHA2_256, interResult, 64/4, true);
        nerd_sha_hal_wait_idle();
        nerd_sha_ll_fill_text_block_sha256_double();
        sha_ll_start_block(SHA2_256);

        nerd_sha_hal_wait_idle();
        sha_ll_load(SHA2_256);
        if (nerd_sha_ll_read_digest_swap_if(hash))
        {
          //~5 per second
          double diff_hash = diff_from_target(hash);
          if (diff_hash > result->difficulty)
          {
            if (isSha256Valid(hash))
            {
              result->difficulty = diff_hash;
              result->nonce = job->nonce_start+n;
              memcpy(result->hash, hash, sizeof(hash));
            }
          }
        }
        if (
             (uint8_t)(n & 0xFF) == 0 &&
             s_working_current_job_id != job_in_work)
        {
          result->nonce_count = n+1;
          break;
        }
      }
      esp_sha_unlock_engine(SHA2_256);
    } else
      vTaskDelay(2 / portTICK_PERIOD_MS);

    esp_task_wdt_reset();
  }
}

#endif  //CONFIG_IDF_TARGET_ESP32

#endif  //HARDWARE_SHA265


#define DELAY 100
#define REDRAW_EVERY 10

void restoreStat() {
  if(!Settings.saveStats) return;
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    Serial.printf("[MONITOR] NVS partition is full or has invalid version, erasing...\n");
    nvs_flash_init();
  }

  ret = nvs_open("state", NVS_READWRITE, &stat_handle);

  size_t required_size = sizeof(double);
  nvs_get_blob(stat_handle, "best_diff", &best_diff, &required_size);
  nvs_get_u32(stat_handle, "Mhashes", &Mhashes);
  uint32_t nv_shares, nv_valids;
  nvs_get_u32(stat_handle, "shares", &nv_shares);
  nvs_get_u32(stat_handle, "valids", &nv_valids);
  shares = nv_shares;
  valids = nv_valids;
  nvs_get_u32(stat_handle, "templates", &templates);
  nvs_get_u64(stat_handle, "upTime", &upTime);

  uint32_t crc = crc32_reset();
  crc = crc32_add(crc, &best_diff, sizeof(best_diff));
  crc = crc32_add(crc, &Mhashes, sizeof(Mhashes));
  crc = crc32_add(crc, &nv_shares, sizeof(nv_shares));
  crc = crc32_add(crc, &nv_valids, sizeof(nv_valids));
  crc = crc32_add(crc, &templates, sizeof(templates));
  crc = crc32_add(crc, &upTime, sizeof(upTime));
  crc = crc32_finish(crc);

  uint32_t nv_crc;
  nvs_get_u32(stat_handle, "crc32", &nv_crc);
  if (nv_crc != crc)
  {
    best_diff = 0.0;
    Mhashes = 0;
    shares = 0;
    valids = 0;
    templates = 0;
    upTime = 0;
  }
}

void saveStat() {
  if(!Settings.saveStats) return;
  Serial.printf("[MONITOR] Saving stats\n");
  nvs_set_blob(stat_handle, "best_diff", &best_diff, sizeof(best_diff));
  nvs_set_u32(stat_handle, "Mhashes", Mhashes);
  nvs_set_u32(stat_handle, "shares", shares);
  nvs_set_u32(stat_handle, "valids", valids);
  nvs_set_u32(stat_handle, "templates", templates);
  nvs_set_u64(stat_handle, "upTime", upTime);

  uint32_t crc = crc32_reset();
  crc = crc32_add(crc, &best_diff, sizeof(best_diff));
  crc = crc32_add(crc, &Mhashes, sizeof(Mhashes));
  uint32_t nv_shares = shares;
  uint32_t nv_valids = valids;
  crc = crc32_add(crc, &nv_shares, sizeof(nv_shares));
  crc = crc32_add(crc, &nv_valids, sizeof(nv_valids));
  crc = crc32_add(crc, &templates, sizeof(templates));
  crc = crc32_add(crc, &upTime, sizeof(upTime));
  crc = crc32_finish(crc);
  nvs_set_u32(stat_handle, "crc32", crc);
}

void resetStat() {
    Serial.printf("[MONITOR] Resetting NVS stats\n");
    templates = hashes = Mhashes = totalKHashes = elapsedKHs = upTime = shares = valids = 0;
    best_diff = 0.0;
    saveStat();
}

void runMonitor(void *name)
{

  Serial.println("[MONITOR] started");
  restoreStat();

  unsigned long mLastCheck = 0;

  resetToFirstScreen();

  unsigned long frame = 0;

  uint32_t seconds_elapsed = 0;

  totalKHashes = (Mhashes * 1000) + hashes / 1000;
  uint32_t last_update_millis = millis();
  uint32_t uptime_frac = 0;

  while (1)
  {
    uint32_t now_millis = millis();
    if (now_millis < last_update_millis)
      now_millis = last_update_millis;
    
    uint32_t mElapsed = now_millis - mLastCheck;
    if (mElapsed >= 1000)
    { 
      mLastCheck = now_millis;
      last_update_millis = now_millis;
      unsigned long currentKHashes = (Mhashes * 1000) + hashes / 1000;
      elapsedKHs = currentKHashes - totalKHashes;
      totalKHashes = currentKHashes;

      uptime_frac += mElapsed;
      while (uptime_frac >= 1000)
      {
        uptime_frac -= 1000;
        upTime ++;
      }

      drawCurrentScreen(mElapsed);

      // Monitor state when hashrate is 0.0
      if (elapsedKHs == 0)
      {
        Serial.printf(">>> [i] Miner: newJob>%s / inRun>%s) - Client: connected>%s / subscribed>%s / wificonnected>%s\n",
            "true",//(1) ? "true" : "false",
            isMinerSuscribed ? "true" : "false",
            client.connected() ? "true" : "false", isMinerSuscribed ? "true" : "false", WiFi.status() == WL_CONNECTED ? "true" : "false");
      }

      #ifdef DEBUG_MEMORY
      Serial.printf("### [Total Heap / Free heap / Min free heap]: %d / %d / %d \n", ESP.getHeapSize(), ESP.getFreeHeap(), ESP.getMinFreeHeap());
      Serial.printf("### Max stack usage: %d\n", uxTaskGetStackHighWaterMark(NULL));
      #endif

      seconds_elapsed++;
      #ifdef NM_TURBO
      static bool stable = false;
      if (!stable && now_millis > 300000)
      {
        stable = true;
        turbo_crash_guard_stable();
      }
      #endif

      if(seconds_elapsed % (saveIntervals[currentIntervalIndex]) == 0){
        saveStat();
        seconds_elapsed = 0;
        if(currentIntervalIndex < saveIntervalsSize - 1)
          currentIntervalIndex++;
      }    
    }
    animateCurrentScreen(frame);
    doLedStuff(frame);

    vTaskDelay(DELAY / portTICK_PERIOD_MS);
    frame++;
  }
}

#ifdef NM_TURBO
//One line of JSON for the status port: raw hash counters (rates are computed by the
//reader from two samples), pool state and the HW self-test results
String turboStatusJson()
{
  char hw[640];
  turbo_hw_status(hw, sizeof(hw));
  char buf[1400];
  snprintf(buf, sizeof(buf),
    "{\"fw\":\"turbo\",\"ms\":%lu,\"up\":%llu,\"hw\":%u,\"sw\":%u,\"khs\":%u,"
    "\"shares\":%u,\"valids\":%u,\"best\":%.6g,\"templates\":%u,\"pool\":%s,%s,"
    "\"swv\":\"%s\",\"sw_cpn\":[%u,%u,%u,%u],\"sw_cand\":%u,\"sw_bad\":%u,"
    "\"loops\":%u,\"hw_starved\":%u,\"sw_starved\":%u,\"temp\":%.1f,\"rssi\":%d,\"heap\":%u,\"asm_chk\":[%u,%u,%u],\"rr\":%d"
    #ifdef NM_TURBO_PROBES
    ",\"probe\":%s"
    #endif
    "}\n",
    (unsigned long)millis(), (unsigned long long)upTime, (unsigned)g_hw_hashes, (unsigned)g_sw_hashes,
    (unsigned)elapsedKHs, (unsigned)shares, (unsigned)valids, best_diff, (unsigned)templates,
    (client.connected() && isMinerSuscribed) ? "true" : "false", hw,
    g_sw_variant >= 0 ? turbo_sw_variants[g_sw_variant].name : "none",
    (unsigned)g_sw_cpn[0], (unsigned)g_sw_cpn[1], (unsigned)g_sw_cpn[2], (unsigned)g_sw_cpn[3], (unsigned)g_sw_cands, (unsigned)g_sw_bad,
    (unsigned)g_strat_loops, (unsigned)g_hw_starved, (unsigned)g_sw_starved,
    temperatureRead(), (int)WiFi.RSSI(), (unsigned)ESP.getFreeHeap(), (unsigned)g_asm_chk, (unsigned)g_asm_got, (unsigned)g_asm_want, (int)esp_reset_reason()
    #ifdef NM_TURBO_PROBES
    , turbo_probe_json()
    #endif
    );
  return String(buf);
}
#endif

#ifdef NM_TURBO
bool turboPoolUp()
{
  return client.connected() && isMinerSuscribed;
}
#endif

#ifdef NM_WIRED
//---------------------------------------------------------------------------------
//Wired mode: no Wi-Fi. The host relay (wired/relay/wired_relay.py) speaks stratum
//to the pool and feeds this board over UART0 (GPIO43 TX / GPIO44 RX) at 921600 baud,
//clocked from the 40 MHz crystal so the link survives a BBPLL overclock.
//  relay -> board:  J <id> <pool diff> <80-byte header hex>   new work (nonce ignored)
//                   P <div>   set BBPLL divider (8 = stock 240 MHz)
//                   A <diff>  a share was accepted        S  status now
//                   D         reboot into the ROM download mode (flash over the wire)
//                   R         reboot
//  board -> relay:  H ...     hello after boot       T {json}  status every 2 s
//                   N <id> <nonce> <diff>   share candidate     p <div> <ok> <us>
#include <hal/uart_ll.h>
#include <soc/rtc_cntl_reg.h>
#include "turbo/turbo_pll.h"
#include "turbo/pie_bench.h"
#include <soc/rtc_cntl_reg.h>
#include <soc/rtc.h>
// RTC watchdog, registers direct (the rtc_wdt_* API is not built into this IDF's esp32s3 libs).
// Clocked from the RTC slow clock (~136 kHz RC), not the PLL. Stage 0 action 4 = full RTC reset.
#define NM_RTCWDT_KEY 0x50D83AA1
static void nm_rtcwdt_start(uint32_t ms)
{
  WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, NM_RTCWDT_KEY);
  WRITE_PERI_REG(RTC_CNTL_WDTCONFIG0_REG, 0);
  WRITE_PERI_REG(RTC_CNTL_WDTCONFIG1_REG, ms * 150);   // slow-clock cycles, ~150 per ms (RC 136-150 kHz)
  WRITE_PERI_REG(RTC_CNTL_WDTCONFIG0_REG, RTC_CNTL_WDT_EN | (4u << RTC_CNTL_WDT_STG0_S) |
                 (7u << RTC_CNTL_WDT_SYS_RESET_LENGTH_S) | (7u << RTC_CNTL_WDT_CPU_RESET_LENGTH_S));
  WRITE_PERI_REG(RTC_CNTL_WDTFEED_REG, RTC_CNTL_WDT_FEED);
  WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, 0);
}
static inline void nm_rtcwdt_feed()
{
  WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, NM_RTCWDT_KEY);
  WRITE_PERI_REG(RTC_CNTL_WDTFEED_REG, RTC_CNTL_WDT_FEED);
  WRITE_PERI_REG(RTC_CNTL_WDTWPROTECT_REG, 0);
}
void turbo_crash_guard_stable();
#include <esp_ota_ops.h>
#include <esp_partition.h>
static esp_ota_handle_t s_ota = 0;
static const esp_partition_t *s_ota_part = NULL;
static uint32_t s_ota_size = 0, s_ota_off = 0;
static char s_ota_sha[65] = "";

#define WIRED_BAUD 921600
static uint32_t s_wired_id = 0;

static void wired_uart_begin()
{
  Serial0.setRxBufferSize(4096);
  Serial0.begin(WIRED_BAUD, SERIAL_8N1, 44, 43);
  uart_ll_set_sclk(&UART0, UART_SCLK_XTAL);
  uart_ll_set_baudrate(&UART0, WIRED_BAUD);
}

static int hexval(char c)
{
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  c |= 0x20;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  return -1;
}

static void wired_status()
{
  String js = turboStatusJson();
  js.trim();
  if (js.endsWith("}"))
    js.remove(js.length() - 1);
  Serial0.printf("T %s,\"pll\":%u,\"ref\":%u,\"mhz\":%u,\"vdig\":%u,\"pll_last_try\":%u,\"wired_id\":%u}\n", js.c_str(),
                 (unsigned)turbo_pll_get(), (unsigned)turbo_pll_ref(), (unsigned)turbo_pll_mhz(), (unsigned)turbo_vdig_get(),
                 (unsigned)turbo_pll_last_try(), (unsigned)s_wired_id);
}

//Called first thing in setup(): 300 ms in which a "D" on the wire reboots into the ROM
//download mode, so a firmware that crashes later in boot can still be reflashed remotely
void wired_boot_window()
{
  wired_uart_begin();
  Serial0.printf("\nB wired boot window\n");
  const uint32_t t0 = millis();
  while (millis() - t0 < 300)
  {
    while (Serial0.available())
      if (Serial0.read() == 0x44)
      {
        Serial0.printf("d\n");
        Serial0.flush();
        REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
        esp_restart();
      }
    delay(5);
  }
}

void runWiredWorker(void *name)
{
  turbo_pll_boot();
  // RTC watchdog: clocked from the RTC slow clock, not the PLL, so it still fires when an overclock
  // has taken the CPU, the task/interrupt watchdogs and the UART down. Full RTC reset (like power-on:
  // PLL, regulator and BBPLL overrides all back to stock). Fed every pass of this loop.
  nm_rtcwdt_start(8000);
  wired_uart_begin();
  Serial0.printf("\nH nerdminer-wired v6 rr=%d pll=%u last_try=%u last_stage=%u\n", (int)esp_reset_reason(),
                 (unsigned)turbo_pll_get(), (unsigned)turbo_pll_last_try(), (unsigned)turbo_pll_last_stage());

  double pool_diff = DEFAULT_DIFFICULTY;
  uint32_t nonce_pool = 0;
  uint32_t job_pool = 0xFFFFFFFF;
  uint32_t hw_midstate[8];
  uint32_t diget_mid[8];
  uint32_t bake[32];
  uint8_t header[128];
  static char line[1200];
  size_t llen = 0;
  uint32_t last_status = millis();
  mMonitor.NerdStatus = NM_Connecting;

  while (true)
  {
    while (Serial0.available())
    {
      int c = Serial0.read();
      if (c == 0x0A || c == 0x0D)
      {
        line[llen] = 0;
        if (llen > 0)
        {
          char cmd = line[0];
          if (cmd == 0x4A && llen > 160)   // J
          {
            char *p = line + 2;
            uint32_t id = strtoul(p, &p, 10);
            double diff = strtod(p, &p);
            while (*p == 0x20) p++;
            bool ok = strlen(p) >= 160;
            for (int i = 0; ok && i < 80; ++i)
            {
              int hi = hexval(p[2 * i]), lo = hexval(p[2 * i + 1]);
              if (hi < 0 || lo < 0) ok = false;
              else header[i] = (uint8_t)(hi << 4 | lo);
            }
            if (ok)
            {
              memset(header + 80, 0, 48);
              header[80] = 0x80;
              header[126] = 0x02;
              header[127] = 0x80;
              {
                std::lock_guard<std::mutex> lock(s_job_mutex);
                s_job_request_list_sw.clear();
                s_job_request_list_hw.clear();
              }
              templates++;
              job_pool++;
              s_working_current_job_id = job_pool & 0xFF;
              s_wired_id = id;
              pool_diff = diff;
              nerd_mids(diget_mid, header);
              turbo_sw_bake(diget_mid, header + 64, bake);
              esp_sha_acquire_hardware();
              sha_hal_hash_block(SHA2_256, header, 64 / 4, true);
              sha_hal_read_digest(SHA2_256, hw_midstate);
              esp_sha_release_hardware();
              nonce_pool = 0;
              mMonitor.NerdStatus = NM_Connecting;
            }
          } else if (cmd == 0x50)   // P
          {
            char *q = line + 2;
            uint8_t div = (uint8_t)strtoul(q, &q, 10);
            uint8_t mode = (uint8_t)strtoul(q, &q, 10);
            uint8_t ref = (uint8_t)strtoul(q, &q, 10);
            uint32_t us = 0;
            bool ok = turbo_pll_set(div, &us, mode, ref);
            wired_uart_begin();
            uint32_t c, l, f;
            turbo_pll_diag(&c, &l, &f);
            Serial0.printf("p %u %d %u cal=%u lock=%u fb=%u ref=%u mhz=%u\n", (unsigned)turbo_pll_get(), ok ? 1 : 0, (unsigned)us, (unsigned)c, (unsigned)l, (unsigned)f, (unsigned)turbo_pll_ref(), (unsigned)turbo_pll_mhz());
          } else if (cmd == 0x51)   // Q <div>: dry run
          {
            char *q = line + 2;
            uint8_t div = (uint8_t)strtoul(q, &q, 10);
            uint8_t mode = (uint8_t)strtoul(q, &q, 10);
            uint8_t ref = (uint8_t)strtoul(q, &q, 10);
            uint32_t us = 0, c, l, f;
            bool ok = turbo_pll_dry(div, &us, mode, ref);
            wired_uart_begin();
            turbo_pll_diag(&c, &l, &f);
            Serial0.printf("q %u %d %u cal=%u lock=%u fb=%u now=%u r8=%02x\n", (unsigned)div, ok ? 1 : 0, (unsigned)us, (unsigned)c, (unsigned)l, (unsigned)f, (unsigned)turbo_pll_get(), (unsigned)turbo_pll_last_r8());
          } else if (cmd == 0x41)   // A
          {
            double d = atof(line + 2);
            if (d > best_diff) best_diff = d;
            shares++;
            if (millis() > 10UL * 60 * 1000) turbo_crash_guard_stable();
          } else if (cmd == 0x53)   // S
            wired_status();
          else if (cmd == 0x44)     // D
          {
            Serial0.printf("d\n");
            Serial0.flush();
            REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
            esp_restart();
          } else if (cmd == 0x4F)   // O <size> <sha256>: update over the wire, start
          {
            char *q = line + 2;
            s_ota_size = strtoul(q, &q, 10);
            while (*q == 0x20) q++;
            strncpy(s_ota_sha, q, 64); s_ota_sha[64] = 0;
            if (s_ota) { esp_ota_abort(s_ota); s_ota = 0; }
            s_ota_part = esp_ota_get_next_update_partition(NULL);
            esp_err_t e = s_ota_part ? esp_ota_begin(s_ota_part, s_ota_size, &s_ota) : ESP_FAIL;
            if (e != ESP_OK) s_ota = 0;
            s_ota_off = 0;
            Serial0.printf("o %d %s\n", e == ESP_OK ? 1 : 0, s_ota_part ? s_ota_part->label : "none");
          } else if (cmd == 0x43)   // C <offset> <hex>
          {
            char *q = line + 2;
            uint32_t off = strtoul(q, &q, 10);
            while (*q == 0x20) q++;
            size_t n = strlen(q) / 2;
            static uint8_t buf[512];
            bool ok = s_ota && off == s_ota_off && n > 0 && n <= sizeof(buf);
            for (size_t i = 0; ok && i < n; ++i)
            {
              int hi = hexval(q[2 * i]), lo = hexval(q[2 * i + 1]);
              if (hi < 0 || lo < 0) ok = false; else buf[i] = (uint8_t)(hi << 4 | lo);
            }
            if (ok && esp_ota_write(s_ota, buf, n) == ESP_OK) { s_ota_off += n; Serial0.printf("c %u\n", (unsigned)s_ota_off); }
            else Serial0.printf("c! %u %u\n", (unsigned)off, (unsigned)s_ota_off);
          } else if (cmd == 0x45)   // E: end, verify, boot it
          {
            esp_err_t e = (s_ota && s_ota_off == s_ota_size) ? esp_ota_end(s_ota) : ESP_FAIL;
            s_ota = 0;
            uint8_t h[32]; char hx[65];
            if (e == ESP_OK)
            {
              esp_partition_get_sha256(s_ota_part, h);
              for (int i = 0; i < 32; ++i) sprintf(hx + 2 * i, "%02x", h[i]);
            }
            else strcpy(hx, "end-failed");
            // esp_partition_get_sha256 hashes the image as written (without the appended digest check), so compare
            // against the file's SHA-256 only when sizes match; esp_ota_end already validated the image itself
            bool ok = e == ESP_OK && esp_ota_set_boot_partition(s_ota_part) == ESP_OK;
            Serial0.printf("e %d %s want %s\n", ok ? 1 : 0, hx, s_ota_sha);
            Serial0.flush();
            if (ok) { delay(200); esp_restart(); }
          } else if (cmd == 0x4B)   // K <reg> <msb> <lsb> <val> | K (clear): BBPLL knobs for the next overclock
          {
            int n;
            if (llen > 2)
            {
              char *q = line + 2;
              uint8_t r = strtoul(q, &q, 10), hi = strtoul(q, &q, 10), lo = strtoul(q, &q, 10), v = strtoul(q, &q, 10);
              n = turbo_knob(r, hi, lo, v);
            }
            else n = turbo_knob(0xff, 0, 0, 0);
            Serial0.printf("k %d\n", n);
          } else if (cmd == 0x58)   // X: BBPLL registers now and at boot
          {
            char b[200]; int o = 0;
            o += snprintf(b + o, sizeof(b) - o, "x now");
            for (int r = 0; r < 16; ++r) o += snprintf(b + o, sizeof(b) - o, " %02x", turbo_bb_reg(r));
            o += snprintf(b + o, sizeof(b) - o, " boot");
            for (int r = 0; r < 16; ++r) o += snprintf(b + o, sizeof(b) - o, " %02x", turbo_bb_boot(r));
            Serial0.printf("%s\n", b);
          } else if (cmd == 0x59)   // Y: stream the coredump partition (the last panic) as hex
          {
            const esp_partition_t *cd = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, NULL);
            uint32_t len = 0;
            if (cd) esp_partition_read(cd, 0, &len, 4);
            if (!cd || len == 0 || len == 0xffffffff || len > cd->size) Serial0.printf("y end 0\n");
            else
            {
              static uint8_t b[192];
              char hx[2 * sizeof(b) + 1];
              for (uint32_t off = 0; off < len; off += sizeof(b))
              {
                const uint32_t n = len - off < sizeof(b) ? len - off : sizeof(b);
                esp_partition_read(cd, off, b, n);
                for (uint32_t i = 0; i < n; ++i) sprintf(hx + 2 * i, "%02x", b[i]);
                Serial0.printf("y %u %s\n", (unsigned)off, hx);
                Serial0.flush();
              }
              Serial0.printf("y end %u\n", (unsigned)len);
            }
          } else if (cmd == 0x42)   // B: PIE SIMD benchmark
          {
            Serial0.printf("%s\n", pie_bench().c_str());
          } else if (cmd == 0x55)   // U: SHA bus / split-burst benchmark
          {
            static char ub[900];
            turbo_bus_bench(ub, sizeof(ub));
            Serial0.printf("b %s\n", ub);
          } else if (cmd == 0x47)   // G: Turbo9 loop experiments
          {
            static char xb[1200];
            turbo_exp_bench_core0(xb, sizeof(xb));
            Serial0.printf("b %s\n", xb);
          } else if (cmd == 0x56)   // V [code]: core voltage
          {
            if (llen > 2) turbo_vdig_set((uint8_t)atoi(line + 2));
            Serial0.printf("v boot=%u now=%u r4=%02x r5=%02x r6=%02x r7=%02x\n", (unsigned)turbo_vdig_boot(), (unsigned)turbo_vdig_get(),
                           turbo_vdig_reg(4), turbo_vdig_reg(5), turbo_vdig_reg(6), turbo_vdig_reg(7));
          } else if (cmd == 0x5A)   // Z: clear the crash guard, reboot (back to the fast engine)
          {
            turbo_crash_guard_stable();
            Serial0.printf("z\n");
            Serial0.flush();
            delay(50);
            esp_restart();
          } else if (cmd == 0x52)   // R
          {
            Serial0.flush();
            esp_restart();
          }
        }
        llen = 0;
      } else if (llen < sizeof(line) - 1)
        line[llen++] = (char)c;
      else
        llen = 0;
    }

    std::list<std::shared_ptr<JobResult>> job_result_list;
    if (job_pool != 0xFFFFFFFF)
    {
      std::lock_guard<std::mutex> lock(s_job_mutex);
      job_result_list.insert(job_result_list.end(), s_job_result_list.begin(), s_job_result_list.end());
      s_job_result_list.clear();
      while (s_job_request_list_sw.size() < 4)
      {
        JobPush(s_job_request_list_sw, job_pool, nonce_pool, NONCE_PER_JOB_SW, pool_diff, header, diget_mid, bake);
        nonce_pool += NONCE_PER_JOB_SW;
      }
      while (s_job_request_list_hw.size() < HW_QUEUE_DEPTH)
      {
        JobPush(s_job_request_list_hw, job_pool, nonce_pool, NONCE_PER_JOB_HW, pool_diff, header, hw_midstate, bake);
        nonce_pool += NONCE_PER_JOB_HW;
      }
    }
    while (!job_result_list.empty())
    {
      std::shared_ptr<JobResult> res = job_result_list.front();
      job_result_list.pop_front();
      hashes += res->nonce_count;
      if (res->difficulty > pool_diff && job_pool == res->id && res->nonce != 0xFFFFFFFF)
        Serial0.printf("N %u %08x %.6g\n", (unsigned)s_wired_id, (unsigned)res->nonce, res->difficulty);
    }
    if (millis() - last_status >= 2000)
    {
      last_status = millis();
      wired_status();
    }
    g_strat_loops++;
    nm_rtcwdt_feed();
    vTaskDelay((s_ota ? 1 : 20) / portTICK_PERIOD_MS);
  }
}
#endif
