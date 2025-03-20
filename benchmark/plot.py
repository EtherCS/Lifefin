import seaborn as sns
import matplotlib.pyplot as plt


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
        sns.set_theme(style="whitegrid")
        plt.figure(figsize=(16, 9))
        plt.plot(commits_df['second'].to_numpy(), commits_df['bps'].to_numpy(), label='Sailfish BPS (Commit)')
        plt.plot(proposals_df['second'].to_numpy(), proposals_df['bps'].to_numpy(), label='Sailfish BPS (Proposal)')
        plt.plot(uncommits_df['second'].to_numpy(), uncommits_df['cul_uncomm_b'].to_numpy(), label='Culmulative Uncommitted Bytes')
        plt.xlabel('Time (seconds)', fontsize=32)
        plt.ylabel('BPS', fontsize=32)
        plt.title('Bytes Per Second (BPS) Over Time', fontsize=32)
        plt.legend(fontsize=28)

        plt.xticks(fontsize=32)
        plt.yticks(fontsize=32)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
