import matplotlib.pyplot as plt
import numpy as np

fig = plt.figure()
ax = fig.add_subplot(111)

x = np.arange(5)
labels = ['7 sw\n(31 rules)', '15 sw\n (45 rules)', '31 sw\n (99 rules)', '63 sw\n (183 rules)', '127 sw\n (347 rules)']

# switches 'physical rules' 'virtual composition' 'physical mapping'
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

# bars
width=0.35
l_grey="#989898"
ll_grey="#B8B8B8"

bar_vct = ax.bar(x, vct, width, color='w', hatch="///", label='Virtual composition time')
bar_pct = ax.bar(x+width, pct, width, color=ll_grey, label='Physical compilation time')

# labels
ax.set_ylabel("Time (ms)")
ax.yaxis.grid()
ax.set_xticks(x+width)
ax.set_xticklabels(labels)

# plt.title("Airnet's compilation time (proactive phase) according to the size the physical topology")
plt.legend(loc='best', shadow=True)

# Pad margins so that markers don't get clipped by the axes
plt.margins(0.05)

plt.show()

