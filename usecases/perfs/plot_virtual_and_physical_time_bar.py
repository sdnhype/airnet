import matplotlib
import matplotlib.pyplot as plt
import numpy as np

matplotlib.rcParams.update({'font.size': 9})
# colors
l_blue="#6699ff"
ll_blue="#99ccff"
d_red="#990000"
l_green="#ccff99"
l_yellow="#ffff66"
l_orange="#ffcc99"
l_grey="#989898"
ll_grey="#B8B8B8"

# Two subplots, unpack the axes array immediately
f, (ax1, ax2) = plt.subplots(1, 2, sharey=True, figsize=(12,5))
# figsize : width, hight in inches

x = np.arange(5)
xlabels1 = ['dataCap\n(7 v.policies)', 'dynLB\n(10 v.policies)', 'staticFW1\n(16 v.policies)', 'dynAuth\n(17 v.policies)', 'staticFW2\n(44 v.policies)']

# data
# UseCase	virtual devices	physical switches	virtual rules	physical rules	compilation duration	enforcing duration
# dataCap	       3	7	7	23	102	18
# dycLoadBalancer	3	8	10	35	103	32
# fabricComposition	5	12	16	55	106	37
# dycAuthentication	4	10	17	56	125	43
# staticFiltering	5	9	44	96	247	86

# Virtual composition time
vct1 = [102, 103, 106, 125, 247]
# Physical compilation time
pct1 = [18, 32, 37, 43, 86]

# bars
width=0.35

# hatch="///"
bar_vct = ax1.bar(x, vct1, width, color=l_blue, hatch="///", label='Virtual composition time')
bar_pct = ax1.bar(x+width, pct1, width, color=d_red, hatch="++", label='Physical mapping time (7$\leq$sw$\leq$12)')

# labels
ax1.set_title("Use cases with different number of virtual policies", weight="bold")
ax1.set_ylabel("Time (ms)")
ax1.yaxis.grid()
ax1.set_xticks(x+width)
ax1.set_xticklabels(xlabels1)
for xtick in ax1.xaxis.get_major_ticks():
	xtick.label.set_fontsize(10)
handles, labels = ax1.get_legend_handles_labels()
ax1.legend(handles, labels, loc='best', shadow=True)
ax1.margins(0.05)

# ==================================================

xlabels2 = ['7 sw\n(31 p.rules)', '15 sw\n (45 p.rules)', '31 sw\n (99 p.rules)', '63 sw\n (183 p.rules)', '127 sw\n (347 p.rules)']

# data
# switches 'physical rules' 'virtual composition' 'physical mapping'
# 7	31	98	20
# 15	45	100	24
# 31	99	101	48
# 63	183	108	135
# 127	347	97	252

# Virtual composition time
vct2 = [98, 100, 101, 108, 97]
# Physical compilation time
pct2 = [20, 24, 48, 135, 252]

# red dashes r-- 
# blue squares bs
# green triangles g^
# x  cross 

# bars
width=0.35

bar_vct = ax2.bar(x, vct2, width, color=l_blue, hatch="///", label='Virtual composition time (12 v.policies)')
bar_pct = ax2.bar(x+width, pct2, width, color=d_red, hatch="++", label='Physical mapping time')

# labels
ax2.set_title("Same use case with different physical topologies", weight="bold")
# ax2.set_ylabel("Time (ms)")
ax2.yaxis.grid()
ax2.set_xticks(x+width)
ax2.set_xticklabels(xlabels2)
for xtick in ax2.xaxis.get_major_ticks():
	xtick.label.set_fontsize(10)
handles, labels = ax2.get_legend_handles_labels()
ax2.legend(handles, labels, loc='best', shadow=True)

# Pad margins so that markers don't get clipped by the axes
ax2.margins(0.05)

plt.tight_layout()
plt.show()

