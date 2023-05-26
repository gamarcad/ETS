from matplotlib import pyplot as pl
import numpy as np
import json
from sys import argv

RESULTS_FILENAME = "execution-times.json"

# create the min, max and mean for each N and each subject
colors = {
    "purchase": ("#CC4F1B", "#FF9848", "-"),
    "refund"  : ("#1B2ACC", "#089FFF", "--"),
    "transfer": ("#258C07", "#7EFF99", "-."),
    "validate": ("#7201EB", "#8072D4", ":")
}

# read the results
INPUT = argv[1]
OUTPUT = argv[2]
with open(INPUT) as file:
    results = json.loads( "".join(file.readlines()) )
    results = results["times"]

def mean( l ): return sum(l) / len(l)

# we compute I and N
subjects = list(results.keys())
I = sorted([ int(i) for i in results[subjects[0]]])
N = I[-1]



# we plot the times
for (index, subject) in enumerate(["purchase", "refund", "transfer", "validate" ]):
    times_mean_purchase = [ mean(results[subject][str(i)]) for i in I ]
    times_min_purchase = [ min(results[subject][str(i)]) for i in I ]
    times_max_purchase = [ max(results[subject][str(i)]) for i in I ]
    (c1, c2, style) = colors[subject]
    ax = pl.subplot( 1,1, 1 )
    ax.set_ylim(bottom=0, top=60)
    pl.plot(I, times_mean_purchase, c1, linestyle=style, label = subject.title())
    pl.fill_between(I, times_min_purchase, times_max_purchase,
        alpha=0.5, edgecolor=c1, facecolor=c2)

pl.xlabel("Number of Handled Tickets", fontsize = 12)
pl.ylabel("Execution Time (ms)", fontsize = 12)
pl.legend(fontsize="13", ncol=2)
pl.savefig(OUTPUT)
exit(0)




for subject, (c1, c2) in colors.items(): 
    N = sorted(results.keys())
    times_min_purchase = [ compute_min( results[n][subject] ) for n in N ]
    times_mean_purchase = [ compute_mean( results[n][subject] ) for n in N ]
    times_max_purchase = [ compute_max( results[n][subject] ) for n in N ]

    # plot the times
    pl.plot(N, times_mean_purchase, '-k')
    pl.fill_between(N, times_min_purchase, times_max_purchase,
        alpha=0.5, edgecolor=c1, facecolor=c2)

pl.show()