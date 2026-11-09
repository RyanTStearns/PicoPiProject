# PicoPiProject
Measuring the cost of forward secrecy utilizing Raspberry Pi Pico 2W.  

Results were gathered using the following hardware :   
  -(1x) Raspberry Pi 4B - used as Wireless Gateway  
  -(2x) Raspberry Pi Pico 2W - used to simulate low-power and constrained IoT device  
  -(2x) INA 219 Power Sensor - used to measure the overhead, or "cost", that correlates with implementing forward-secrecy  


The directory structure is as follows :   
  -[1] MicroPython_Pico_Files - contains Pico Protocol MicoPython files that were tested on Pico 2W's.  
  -[2] Python_Crypto_Files - contains the cryptography utilities files that were used for testing on the Gateway and Pico 2W's.  
  -[3] Python_Gateway_Files - contains the various gateway protocol versions used in testing on the Raspberry Pi 4B. (Gateway).  
  -[4] Python_Other_Files - contains any other test files used in implementation.  
  -[5] Python_Power_Analysis_Files - contains the power analysis python scripts used to calculate power used during handshakes.  
  -[6] V1 - contains Version 1 tests, utilizing the V1 gateway and pico protocols. Basic connection test.  
  -[7] V2 - contains Version 2 tests, utilizing the V2 gateway and pico protocols. Testing power analysis with connection.
  -[8] V3 - contains Version 3 tests, utilizing the V3 gateway and pico protocols. Testing reason for errors on (~10%) handshakes.
  -[9] V3_burst - contains Version 3_burst tests, utilizes the V3 gateway and V3_burst pico protocols. Testing if sending packets in burst fixes error.
  -[10] V4 - contains Version 4 tests, utilizing the V4 gateway and pico protocols.  Testing forward-secrecy implementation.
  -[11] V5_PreComp_Marked - contains (FINAL) Version 5 tests, utilizing the V4 gateway, and v5_precomp_marked pico protocols.  



  Detailed description for Version Folders :  
    - Each version will contain two folders, "P1" and "P2", where P1 = Pico2W-1 and P2 = Pico2W-2.  
    - Each P1 & P2 folder will contain five folders "a" "b" "c" "d" and "e".  Each of these folders is a single test instance.  
    - Each a/b/c/d/e folder will contain the text files "Results.txt" and "Thonny.txt" where Results.txt = Output of Power Analysis and Thonny.txt = Pico Output  
    - 
