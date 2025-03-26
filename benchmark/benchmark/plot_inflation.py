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


    def preprocess(self, plot_interval):
        parser = self.parser

        start, end = min([min(parser.proposals.values()), min(parser.start)]), max(parser.proposals.values())
        commits_by_second = group_by_second(parser.commits, start, end)
        proposals_by_second = group_by_second(parser.proposals, start, end)

        bytes_of_commits_by_second = []
        previous_second = 0
        last_commit_time = 0
        culmulative_total_commit_bytes = 0
        last_culmulative_total_commit_bytes = 0
        for second, commits in commits_by_second:
            # plot 0s for seconds with no commits
            if second - previous_second > plot_interval:
                for intverval in range(math.ceil(previous_second) + plot_interval, math.ceil(second), plot_interval):
                    bytes_of_commits_by_second.append((intverval, 0, 0, culmulative_total_commit_bytes))
            total_bytes = sum([parser.sizes[k] for k, _ in commits if k in parser.sizes])
            if total_bytes == 0:
                continue
            culmulative_total_commit_bytes += total_bytes # record total committed bytes so far
            bps = total_bytes / (second - previous_second)
            tps = bps / parser.size[0]
            previous_second = second
            bytes_of_commits_by_second.append((second, bps, tps, culmulative_total_commit_bytes))
            last_commit_time = second
            last_culmulative_total_commit_bytes = culmulative_total_commit_bytes
        
        bytes_of_proposals_by_second = []
        previous_second = 0
        culmulative_total_proposal_bytes = 0
        for second, proposals in proposals_by_second:
            # plot 0s for seconds with no commits
            # if second - previous_second > plot_interval:
            #     for intverval in range(math.ceil(previous_second) + plot_interval, math.ceil(second), plot_interval):
            #         bytes_of_proposals_by_second.append((intverval, 0, 0, culmulative_total_proposal_bytes))
            total_bytes = sum([parser.total_sizes[k] for k, t in proposals if k in parser.total_sizes])
            if total_bytes == 0:
                continue
            culmulative_total_proposal_bytes += total_bytes 
            bps = total_bytes / (second - previous_second)
            tps = bps / parser.size[0]
            previous_second = second
            bytes_of_proposals_by_second.append((second, bps, tps, culmulative_total_proposal_bytes))
            if second > last_commit_time:
                bytes_of_commits_by_second.append((second, 0, 0, last_culmulative_total_commit_bytes))

        culmulative_uncommitted_bytes = [] # record culmulative uncommitted bytes
        for s_p, _, _, cul_prop_b in bytes_of_proposals_by_second:
            last_cul_comm_b = 0
            for s_c, _, _, cul_comm_b in bytes_of_commits_by_second:
                if s_c >= s_p:
                    culmulative_uncommitted_bytes.append((s_p, cul_prop_b - last_cul_comm_b))
                    break
                last_cul_comm_b = cul_comm_b
        
        commits_df = pd.DataFrame(bytes_of_commits_by_second, columns=['second', 'bps', 'tps', 'cul_comm_b'])
        proposals_df = pd.DataFrame(bytes_of_proposals_by_second, columns=['second', 'bps', 'tps', 'cul_prop_b'])
        uncommits_df = pd.DataFrame(culmulative_uncommitted_bytes, columns=['second', 'cul_uncomm_b'])

        return commits_df, proposals_df, uncommits_df


    def plot(self, output_path, plot_interval):
        commits_df, proposals_df, uncommits_df = self.preprocess(plot_interval)
        if commits_df.empty or proposals_df.empty or uncommits_df.empty:
            print("No data to plot.")
            return
        
        # Plotting the data
        # sns.set_theme(style="whitegrid")
        # plt.figure(figsize=(16, 9))
        # plt.plot(commits_df['second'].to_numpy(), commits_df['bps'].to_numpy(), label='Sailfish BPS (Commit)')
        # plt.plot(proposals_df['second'].to_numpy(), proposals_df['bps'].to_numpy(), label='Sailfish BPS (Proposal)')
        # plt.plot(uncommits_df['second'].to_numpy(), uncommits_df['cul_uncomm_b'].to_numpy(), label='Culmulative Uncommitted Bytes')
        # plt.xlabel('Time (seconds)', fontsize=32)
        # plt.ylabel('BPS', fontsize=32)
        # plt.title('Bytes Per Second (BPS) Over Time', fontsize=32)
        # plt.legend(fontsize=28)

        # plt.xticks(fontsize=32)
        # plt.yticks(fontsize=32)
        # plt.savefig(output_path, dpi=300, bbox_inches='tight')

        sns.set_theme(style="whitegrid")
        fig, ax1 = plt.subplots(figsize=(9, 9))

        # Left Y-axis (Bytes Per Second - BPS)
        ax1.plot(commits_df['second'].to_numpy(), commits_df['bps'].to_numpy(), label='Committed BPS', color='red', marker='v', markersize=10, linewidth=4)
        ax1.plot(proposals_df['second'].to_numpy(), proposals_df['bps'].to_numpy(), label='Proposed BPS', color='green', marker='*', markersize=10, linewidth=4)

        ax1.set_xlabel('Running Time (seconds)', fontsize=36)
        ax1.set_ylabel('Bytes Per Second (BPS)', fontsize=36, color='black')
        ax1.tick_params(axis='y', labelcolor='black')

        # Create right Y-axis (Bytes) with the same range as the left Y-axis
        ax2 = ax1.twinx()
        ax2.plot(uncommits_df['second'].to_numpy(), uncommits_df['cul_uncomm_b'].to_numpy(), 
                label='Cumulative UB', color='orange', marker='D', markersize=10, linewidth=4)

        ax2.set_ylabel('Uncommitted Bytes (UB)', fontsize=36, color='black')
        ax2.tick_params(axis='y', labelcolor='black')

        # Ensure both y-axes share the same limits
        min_y = min(commits_df['bps'].min(), proposals_df['bps'].min(), uncommits_df['cul_uncomm_b'].min())
        max_y = max(commits_df['bps'].max(), proposals_df['bps'].max(), uncommits_df['cul_uncomm_b'].max())
        ax1.set_ylim(min_y, max_y)
        ax2.set_ylim(min_y, max_y)
    
        # Enlarging x-axis tick labels
        ax1.tick_params(axis='x', labelsize=36)
        
        # Set x-axis ticks with an interval of 20
        x_ticks = range(0, int(commits_df['second'].max())+1, 20)
        ax1.set_xticks(x_ticks)
        
        # Increase the size of scientific notation text (offset text)
        ax1.yaxis.get_offset_text().set_fontsize(32)
        ax2.yaxis.get_offset_text().set_fontsize(32)
        
        plt.xticks(fontsize=36)
        ax1.yaxis.set_tick_params(labelsize=36)
        ax2.yaxis.set_tick_params(labelsize=36)

        # Make all four spines (borders) black
        for spine in ax1.spines.values():
            spine.set_color('black')
            spine.set_linewidth(2)  # Optional: Make border thicker for visibility

        for spine in ax2.spines.values():
            spine.set_color('black')
            spine.set_linewidth(2)  
            
        # Set fixed y-axis limits for zooming in
        ax1.set_ylim(0.0, 1e8)
        ax2.set_ylim(0.0, 3e9)
        
        # Legends
        ax1_lines, ax1_labels = ax1.get_legend_handles_labels()
        ax2_lines, ax2_labels = ax2.get_legend_handles_labels()
        legend = ax1.legend(ax1_lines + ax2_lines, ax1_labels + ax2_labels, fontsize=32, loc='upper left', frameon=True, facecolor='white', framealpha=1, fancybox=True)
        # Set the zorder of the legend's frame to bring it to the front
        legend.set_zorder(10)
        
        # Remove gridlines
        ax1.grid(False)  # Disable gridlines on the left axis
        ax2.grid(False)  # Disable gridlines on the right axis

        # Set a thicker border for the legend
        legend.get_frame().set_linewidth(2)

        plt.savefig(output_path, dpi=300, bbox_inches='tight')