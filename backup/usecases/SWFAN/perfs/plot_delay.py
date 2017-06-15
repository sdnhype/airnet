import matplotlib.pyplot as plt
import numpy as np

x = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

# Delay 20 oct 2015
# ARP delay = (25.8 + 13.6 + 14.7)/3 = 18.03 (dataCompress without dataFct)
ping_c1 = [18.03, 0.094, 0.083, 0.083, 0.094, 0.095, 0.085, 0.086, 0.097, 0.083]
ping_c2 = [21.62, 2.51, 2.44, 2.67, 2.55, 2.67, 2.56, 2.64, 2.60, 2.49]
ping_c3 = [29.21, 8.26, 8.30, 7.14, 8.26, 7.21, 7.84, 7.15, 7.47, 7.30]
ping_c4 = [95.8, 0.195, 0.070, 0.052, 0.085, 0.053, 0.053, 0.085, 0.083, 0.052]

# Delay 16 nov 2015
#ping_c1 = [44.4, 0.140, 0.140, 0.138, 0.141, 0.138, 0.138, 0.137, 0.138, 0.131]
#ping_c2 = [30.2, 39.0, 40.9, 49.3, 10.8, 23.9, 37.0, 47.3, 24.9, 39.0]
#ping_c3 = [125, 0.330, 0.139, 0.139, 0.139, 0.139, 0.138, 0.140, 0.141, 0.179]

# red dashes r-- 
# blue squares bs
# green triangles g^
# x  cross 

plt.plot(x, ping_c1, linestyle='--', marker='o', color='b', label='No network function')
plt.plot(x, ping_c2, linestyle='--', marker='s', color='g', label='Data function _ 3ms')
plt.plot(x, ping_c3, linestyle='--', marker='s', color='g', label='Data function _ 7ms')
plt.plot(x, ping_c4, linestyle='--', marker='^', color='r', label='Dynamic control function')


plt.grid(True, which='both')
plt.xticks(x, x)

plt.title("Delay (Topology with 11 physical switches)")
plt.ylabel("RTT (ms)")
plt.legend(loc='best', shadow=True)

# Pad margins so that markers don't get clipped by the axes
plt.margins(0.05)

plt.show()

