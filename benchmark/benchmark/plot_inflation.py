import math
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from collections import defaultdict

from benchmark.logs import LogParser
from benchmark.utils import PathMaker


# helper function to group data by second
def group_by_second(data, start_time, end_time=None):
    if not data:
        return []

    groups = defaultdict(list)

    for key, timestamp in data.items():
        group_index = math.ceil(timestamp - start_time)
        if group_index > (end_time - start_time):
            group_index = end_time - start_time
        groups[group_index].append((key, timestamp))

    sorted_group_indices = sorted(groups.keys())
    return [(i, groups[i]) for i in sorted_group_indices]


class InflationPlotter:
    def __init__(self, burst, faults):
        self.burst = burst
        self.faults = faults
        self.parser = LogParser.process(PathMaker.logs_path(), burst=burst, faults=faults)


    def preprocess(self):
        parser = self.parser

        start, end = min([min(parser.proposals.values()), min(parser.start)]), max(parser.proposals.values())
        commits_by_second = group_by_second(parser.commits, start, end)
        proposals_by_second = group_by_second(parser.proposals, start, end)

        bytes_of_commits_by_second = []
        previous_second = 0
        for second, commits in commits_by_second:
            total_bytes = sum([parser.sizes[k] for k, _ in commits if k in parser.sizes])
            if total_bytes == 0:
                continue
            bps = total_bytes / (second - previous_second)
            tps = bps / parser.size[0]
            previous_second = second
            bytes_of_commits_by_second.append((second, bps, tps))
        

        bytes_of_proposals_by_second = []
        previous_second = 0
        for second, proposals in proposals_by_second:
            total_bytes = sum([parser.total_sizes[k] for k, t in proposals if k in parser.total_sizes])
            if total_bytes == 0:
                continue
            bps = total_bytes / (second - previous_second)
            tps = bps / parser.size[0]
            previous_second = second
            bytes_of_proposals_by_second.append((second, bps, tps))

        commits_df = pd.DataFrame(bytes_of_commits_by_second, columns=['second', 'bps', 'tps'])
        proposals_df = pd.DataFrame(bytes_of_proposals_by_second, columns=['second', 'bps', 'tps'])

        return commits_df, proposals_df


    def plot(self, output_path):
        commits_df, proposals_df = self.preprocess()
        if commits_df.empty or proposals_df.empty:
            print("No data to plot.")
            return
        
        # Plotting the data
        sns.set_theme(style="whitegrid")
        plt.figure(figsize=(16, 9))
        plt.plot(commits_df['second'], commits_df['bps'], label='Sailfish BPS (Commit)')
        plt.plot(proposals_df['second'], proposals_df['bps'], label='Sailfish BPS (Proposal)')
        plt.xlabel('Time (seconds)', fontsize=32)
        plt.ylabel('BPS', fontsize=32)
        plt.title('Bytes Per Second (BPS) Over Time', fontsize=32)
        plt.legend(fontsize=28)

        plt.xticks(fontsize=32)
        plt.yticks(fontsize=32)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')

