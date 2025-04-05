import seaborn as sns
import matplotlib.pyplot as plt
from mpl_toolkits.axes_grid1.inset_locator import inset_axes, mark_inset


class Plotter:
    def __init__(self, created_block_df, committed_block_df, uncommitted_bytes_df):
        self.commits_df = created_block_df
        self.proposals_df = committed_block_df
        self.uncommits_df = uncommitted_bytes_df


    def plot(self, output_path):
        if self.commits_df.empty or self.proposals_df.empty or self.uncommits_df.empty:
            print("No data to plot")
            return
        commits_df = self.commits_df
        proposals_df = self.proposals_df
        uncommits_df = self.uncommits_df
        # Plotting the data
        # sns.set_theme(style="whitegrid")
        # plt.figure(figsize=(16, 9))
        # plt.plot(commits_df['second'].to_numpy(), commits_df['bps'].to_numpy(), label='Commit BPS')
        # plt.plot(proposals_df['second'].to_numpy(), proposals_df['bps'].to_numpy(), label='Proposal BPS')
        # plt.plot(uncommits_df['second'].to_numpy(), uncommits_df['cul_uncomm_b'].to_numpy(), label='Culmulative Uncommitted Bytes')
        # plt.xlabel('Running Time (seconds)', fontsize=32)
        # plt.ylabel('Bytes Per Second (BPS)', fontsize=32)
        # plt.legend(fontsize=28)

        # plt.xticks(fontsize=32)
        # plt.yticks(fontsize=32)
        # plt.savefig(output_path, dpi=300, bbox_inches='tight')
        
        sns.set_theme(style="whitegrid")
        fig, ax1 = plt.subplots(figsize=(16, 9))

        # Left Y-axis (Bytes Per Second - BPS)
        ax1.plot(commits_df['second'].to_numpy(), commits_df['bps'].to_numpy(), label='Committed BPS', color='red', marker='v', markersize=10, linewidth=4)
        ax1.plot(proposals_df['second'].to_numpy(), proposals_df['bps'].to_numpy(), label='Proposed BPS', color='grey', marker='*', markersize=10, linewidth=4)

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
        x_ticks = range(0, int(commits_df['second'].max()), 20)
        ax1.set_xticks(x_ticks)
        # ax1.set_xlim(0, 80)
        
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
        ax1.set_ylim(0.0, 2e8)
        ax2.set_ylim(0.0, 1e9)
        
        # Set y-axis ticks for ax2 with an interval of 3e8
        # y_ticks = [i * 3e8 for i in range(0, 6)]  # Generate ticks: 0, 3e8, 6e8, ..., 1.5e9
        # ax2.set_yticks(y_ticks)
        
        # Legends
        ax1_lines, ax1_labels = ax1.get_legend_handles_labels()
        ax2_lines, ax2_labels = ax2.get_legend_handles_labels()
        legend = ax1.legend(ax1_lines + ax2_lines, ax1_labels + ax2_labels, fontsize=32, loc='upper left', frameon=True, facecolor='white', framealpha=1, fancybox=True)
        
        # Remove gridlines
        ax1.grid(False)  # Disable gridlines on the left axis
        ax2.grid(False)  # Disable gridlines on the right axis

        # Set a thicker border for the legend
        legend.get_frame().set_linewidth(2)

        plt.savefig(output_path, dpi=300, bbox_inches='tight')
