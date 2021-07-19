// ESP8266 Simple sniffer
// 2018 Carve Systems LLC
// Angel Suarez-B Martin

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include "sdk_structs.h"
#include "ieee80211_structs.h"
#include "string_utils.h"

#define RefreshRate 1000
#define RefreshRate2 10000

WiFiUDP UDP;

extern "C"
{
#include "user_interface.h"
}

uint8_t Channel = 1;
uint64_t LastCheck = RefreshRate;
uint64_t SendTimeout = RefreshRate2;
String mm = String("MM");
String mm_guest = String("MM-Guest");
String mm_cast = String("MM-CAST");
String mm_mobile = String("MM-Mobile");
static uint16_t MM = 0;
static uint16_t MM_Guest = 0;
static uint16_t MM_Cast = 0;
static uint16_t MM_Mobile = 0;
static uint16_t Total = 0;

// According to the SDK documentation, the packet type can be inferred from the
// size of the buffer. We are ignoring this information and parsing the type-subtype
// from the packet header itself. Still, this is here for reference.
wifi_promiscuous_pkt_type_t packet_type_parser(uint16_t len)
{
  switch (len)
  {
  // If only rx_ctrl is returned, this is an unsupported packet
  case sizeof(wifi_pkt_rx_ctrl_t):
    return WIFI_PKT_MISC;

  // Management packet
  case sizeof(wifi_pkt_mgmt_t):
    return WIFI_PKT_MGMT;

  // Data packet
  default:
    return WIFI_PKT_DATA;
  }
}

void SendData()
{
}

// In this example, the packet handler function does all the parsing and output work.
// This is NOT ideal.
void wifi_sniffer_packet_handler(uint8_t *buff, uint16_t len)
{
  // First layer: type cast the received buffer into our generic SDK structure
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  // Second layer: define pointer to where the actual 802.11 packet is within the structure
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  // Third layer: define pointers to the 802.11 packet header and payload
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  const uint8_t *data = ipkt->payload;

  // Pointer to the frame control section within the packet header
  const wifi_header_frame_control_t *frame_ctrl = (wifi_header_frame_control_t *)&hdr->frame_ctrl;

  // Parse MAC addresses contained in packet header into human-readable strings
  char addr1[] = "00:00:00:00:00:00\0";
  char addr2[] = "00:00:00:00:00:00\0";
  char addr3[] = "00:00:00:00:00:00\0";

  mac2str(hdr->addr1, addr1);
  mac2str(hdr->addr2, addr2);
  mac2str(hdr->addr3, addr3);
  if (frame_ctrl->type == WIFI_PKT_MGMT && frame_ctrl->subtype == BEACON)
  {
    const wifi_mgmt_beacon_t *beacon_frame = (wifi_mgmt_beacon_t *)ipkt->payload;
    char ssid[32] = {0};
    if (beacon_frame->tag_length >= 32)
    {
      strncpy(ssid, beacon_frame->ssid, 31);
    }
    else
    {
      strncpy(ssid, beacon_frame->ssid, beacon_frame->tag_length);
    }
    String SSID = String(ssid[0]) + String(ssid[1]);
    if (SSID.equals("MM"))
    {
      SSID = String(ssid);
      /*
      Serial.printf("\n%s | %s | %s | %u | %02d | %u | %u(%-2u) | %-28s | %u | %u | %u | %u | %u | %u | %u | %u | ",
                    addr1,
                    addr2,
                    addr3,
                    wifi_get_channel(),
                    ppkt->rx_ctrl.rssi,
                    frame_ctrl->protocol,
                    frame_ctrl->type,
                    frame_ctrl->subtype,
                    wifi_pkt_type2str((wifi_promiscuous_pkt_type_t)frame_ctrl->type, (wifi_mgmt_subtypes_t)frame_ctrl->subtype),
                    frame_ctrl->to_ds,
                    frame_ctrl->from_ds,
                    frame_ctrl->more_frag,
                    frame_ctrl->retry,
                    frame_ctrl->pwr_mgmt,
                    frame_ctrl->more_data,
                    frame_ctrl->wep,
                    frame_ctrl->strict);
      Serial.printf("%s\n", ssid);
      */
      if (SSID.equals(mm_cast))
        MM_Cast++;
      else if (SSID.equals(mm_guest))
        MM_Guest++;
      else if (SSID.equals(mm_mobile))
        MM_Mobile++;
      else
        MM++;
    }
    else
      Total++;
  }
}

void setup()
{
  // Serial setup
  Serial.begin(115200);
  delay(10);
  wifi_set_channel(3);

  // Wifi setup
  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(0);
  WiFi.disconnect();

  // Set sniffer callback
  wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
  wifi_promiscuous_enable(1);
}

void loop()
{
  delay(10000);
  SendTimeout = SendTimeout + RefreshRate2;
  Serial.print("Shut promiscuous down\n");
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(0);
  wifi_promiscuous_enable(1);
  wifi_promiscuous_enable(0);
  Serial.print("Connecting to WiFi\n");
  WiFi.mode(WIFI_STA);
  WiFi.begin("MM", "mmdirecao@");
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(50);
    Serial.print(".");
  }
  Serial.print("Wifi connectado a:");
  Serial.println(WiFi.localIP());

  Serial.print("Wifi connectado a:");
  Serial.println(WiFi.localIP());
  StaticJsonDocument<255> doc;
  String frame;
  doc["MM"] = MM;
  doc["MM_Cast"] = MM_Cast;
  doc["MM_Guest"] = MM_Guest;
  doc["MM_Mobile"] = MM_Mobile;
  doc["MM_Total"] = MM + MM_Cast + MM_Guest + MM_Mobile;
  doc["Total"] = Total + MM + MM_Cast + MM_Guest + MM_Mobile;
  serializeJson(doc, frame);
  UDP.begin(1150);
  Serial.print("Sending UDP\n");
  UDP.flush();
  UDP.beginPacket("34.67.7.11", 1980);
  UDP.print(frame);
  UDP.endPacket();
  UDP.flush();
  delay(2000);
  //Serial.printf("MM: %d, MM_Cast: %d, MM_Guest: %d, MM_Mobile: %d, Total: %d\n",MM,MM_Cast,MM_Guest,MM_Mobile,Total);
  MM = 0;
  MM_Cast = 0;
  MM_Guest = 0;
  MM_Mobile = 0;
  Total = 0;
  ESP.reset();
}
