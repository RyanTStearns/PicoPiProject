# Version 5 (V5)
**Updated to precompute keys during idle time**

Utilizes files :  
  -Python_Gateway_Files > gateway_protocol_v4.py  
  -Python_Crypto_Files > crypto_utils.py, x25519.py  
  -MicroPython_Pico_Files > pico_protocol_v5_precomp_marked_p1.py, pico_protocol_v5_precomp_marked_p2.py  
  -Python_Power_Analysis_Files > analyze_power_three_window.py  
  -Python_Other_Files > precompute_marker_logger.py  



Each Pico 2W ran the MicroPython script while the output was observed in Thonny :  
  -[1] - pico_protocol_v3_batch_px.py (where x is set to the Pico #). 
  
The Pi 4B (Gateway) ran the following Python scripts simultaneously :  
  -[1] - power_logger.py  
  -[2] - gateway_protocol_v4.py  
  -[3] - precompute_marker_logger.py  
  -[4] - Wireshark  

LEGEND  
P1 = Pico 2W-1  
P2 = Pico 2W-2  

  a = Test #1.  
  b = Test #2.   
  c = Test #3.  
  d = Test #4.  
  e = Test #5.   

