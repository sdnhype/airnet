import matplotlib.pyplot as plt
import numpy as np

x = [7, 15, 31, 63, 127]
labels = ['7\n(31 r)', '15\n (45 r)', '31\n (99 rules)', '63\n (183 rules)', '127\n (347 rules)']

# switches    physical rules    compilation duration	enforcing duration
# 7	31	98	20
# 15	45	100	24
# 31	99	101	48
# 63	183	108	135
# 127	347	97	252

# Virtual composition time
vct = [98, 100, 101, 108, 97]
# Physical compilation time
pct = [20, 24, 48, 135, 252]

# red dashes r-- 
# blue squares bs
# green triangles g^
# x  cross 

plt.plot(x, vct, linestyle='--', marker='o', color='b', label='Virtual composition time')
plt.plot(x, pct, linestyle='--', marker='^', color='r', label='Physical compilation time')
# plt.plot(x, vct, 'bo', label='Virtual composition time')
# plt.plot(x, pct, 'r^', label='Physical compilation time')


plt.grid(True, which='both')
plt.xticks(x, labels)
ax = plt.gca() # get current axes
for xtick in ax.xaxis.get_major_ticks():
	xtick.label.set_fontsize(10)

# plt.title("Airnet's compilation time (proactive phase) according to the size the physical topology")
plt.ylabel("Time (ms)")
plt.xlabel("Number of physical switches")
plt.legend(loc='best', shadow=True)

# Pad margins so that markers don't get clipped by the axes
plt.margins(0.05)

plt.show()

