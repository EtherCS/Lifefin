import math
import networkx as nx
import pandas as pd
import pathlib
import re

from collections import defaultdict
from multiprocessing import cpu_count
from multiprocessing.dummy import Pool


TIMESTAMP_PATTERN = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z"
CREATE_PATTERN = r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z).*?Created block (?P<block_id>\w+):\[(?P<parents>[^\]]*)\]\((?P<txs>[^)]*)\)"
COMMIT_PATTERN = r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z).*?(Decided Commit|Outcome of direct rule: Commit)\((?P<commit_id>\w+)\)"

ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


def parse_log(log_file):
    created_blocks = []
    committed_blocks = []
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
        line = ESCAPE.sub('', lines[0].strip())
        start_time = re.match(TIMESTAMP_PATTERN, line).group(0)
        start_time = pd.to_datetime(start_time).timestamp()

        for line in lines[1::]:
            line = ESCAPE.sub('', line.strip())

            create_match = re.match(CREATE_PATTERN, line)
            if create_match:
                created_blocks.append(create_match.groupdict())
            commit_match = re.match(COMMIT_PATTERN, line)
            if commit_match:
                committed_blocks.append(commit_match.groupdict())
        
        end_time = re.match(TIMESTAMP_PATTERN, line).group(0)
        end_time = pd.to_datetime(end_time).timestamp()
    
    return start_time, end_time, created_blocks, committed_blocks


class Block:
    def __init__(self, label, create_time, parents, txns_count, block_size=512, tx_size=512):
        self.label = label
        self.create_time = create_time
        self.parents = parents
        self.txns_count = txns_count
        self.commited = False
        self.commit_time = None
        self.block_size = block_size
        self.tx_size = tx_size
    
    def commit(self, time):
        self.commited = True
        if self.commit_time is None:
            self.commit_time = time
        else:
            self.commit_time = min(self.commit_time, time)

    def get_size(self):
        return self.txns_count * self.tx_size + self.block_size
    

    def __repr__(self):
        return f"Block({self.label}):, created: {self.create_time}, commited: {self.commited}, commit_time: {self.commit_time}, size: {self.get_size()}"
    

class Parser:
    def __init__(self, block_size=512, tx_size=512):
        self.graph = nx.DiGraph()
        self.blocks = {}
        self.block_size = block_size
        self.tx_size = tx_size
    

    def parse_logs(self, log_dir):
        logs = list(pathlib.Path(log_dir).rglob('*.ansi'))

        with Pool(min(cpu_count(), len(logs))) as p:
            results = p.map(parse_log, logs)
        
        created_blocks = []
        committed_blocks = []
        self.start_time = float('inf')
        self.end_time = float('-inf')
        for start_time, end_time, created, committed in results:
            created_blocks.extend(created)
            committed_blocks.extend(committed)

            self.start_time = min(self.start_time, start_time)
            self.end_time = max(self.end_time, end_time)

        committed_df = pd.DataFrame(committed_blocks)
        committed_df["timestamp"] = pd.to_datetime(committed_df["timestamp"])
        committed_df = committed_df.sort_values(by="timestamp")
        committed_df_dedup = committed_df.drop_duplicates(subset="commit_id", keep="first").reindex()
        committed_df_dedup["timestamp"] = committed_df_dedup["timestamp"].apply(lambda x: x.timestamp())

        for block in created_blocks:
            block_id = block["block_id"]
            timestamp = pd.to_datetime(block["timestamp"]).timestamp()
            parents = block["parents"].split(",")
            parents = [parent for parent in parents if parent != ""]
            txs = block["txs"].split(",")
            self.blocks[block_id] = Block(block_id, timestamp, parents, len(txs), self.block_size, self.tx_size)
            # DAG path
            for parent in parents:
                self.graph.add_edge(block_id, parent)
        
        for node in self.graph.nodes:
            if node not in self.blocks and node.endswith("0"):
                self.blocks[node] = Block(node, start_time, [], 0)
        
        for commit in committed_df_dedup.itertuples():
            block_id = commit.commit_id
            timestamp = commit.timestamp
            if block_id in self.blocks:
                self.graph_commit(block_id, timestamp)


    def get_created_blocks_by_seconds(self, start_time, end_time):
        groups = defaultdict(list)

        for node, block in self.blocks.items():
            group_index = math.ceil(block.create_time - start_time)
            if group_index > (end_time - start_time):
                group_index = end_time - start_time
            groups[group_index].append(node)

        sorted_group_indices = sorted(groups.keys())
        return [(i, groups[i]) for i in sorted_group_indices]


    def get_committed_blocks_by_seconds(self, start_time, end_time):
        groups = defaultdict(list)

        for node, block in self.blocks.items():
            if block.commited:
                group_index = math.ceil(block.commit_time - start_time)
                if group_index > (end_time - start_time):
                    group_index = end_time - start_time
                groups[group_index].append(node)
        
        sorted_group_indices = sorted(groups.keys())
        return [(i, groups[i]) for i in sorted_group_indices]


    def get_metrics_data(self):

        # Calculate the bytes per second for the committed blocks (commits)
        committed_blocks_by_second = self.get_committed_blocks_by_seconds(self.start_time, self.end_time)
        bytes_of_commits_by_second = []
        previous_second = 0
        last_commit_time = 0
        last_culmulative_total_commit_bytes = 0
        culmulative_total_commit_bytes = 0
        for second, commits in committed_blocks_by_second:
            total_bytes = sum([self.blocks[node].get_size() for node in commits])
            if total_bytes == 0:
                continue
            culmulative_total_commit_bytes += total_bytes
            bps = total_bytes / (second - previous_second)
            tps = bps / self.tx_size
            previous_second = second
            bytes_of_commits_by_second.append((second, bps, tps, culmulative_total_commit_bytes))
            last_commit_time = second
            last_culmulative_total_commit_bytes = culmulative_total_commit_bytes

        # Calculate the bytes per second for the created blocks (proposals)
        created_blocks_by_second = self.get_created_blocks_by_seconds(self.start_time, self.end_time)
        bytes_of_proposals_by_second = []
        previous_second = 0
        culmulative_total_proposal_bytes = 0
        for second, proposals in created_blocks_by_second:
            total_bytes = sum([self.blocks[node].get_size() for node in proposals])
            if total_bytes == 0:
                continue
            culmulative_total_proposal_bytes += total_bytes 
            bps = total_bytes / (second - previous_second)
            tps = bps / self.tx_size
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

        created_block_df = pd.DataFrame(bytes_of_proposals_by_second, columns=["second", "bps", "tps", "culmulative_total_proposal_bytes"])
        committed_block_df = pd.DataFrame(bytes_of_commits_by_second, columns=["second", "bps", "tps", "culmulative_total_commit_bytes"])
        uncommitted_bytes_df = pd.DataFrame(culmulative_uncommitted_bytes, columns=["second", "cul_uncomm_b"])

        return created_block_df, committed_block_df, uncommitted_bytes_df
            

    # Commit all blocks that are reachable from the given block
    def graph_commit(self, block_id, timestamp):
        reachable_nodes = nx.descendants(self.graph, block_id)
        for node in reachable_nodes:
            self.blocks[node].commit(timestamp)


    def get_graph(self):
        return self.graph
    

    def get_duration(self):
        return self.end_time - self.start_time


if __name__ == "__main__":
    parser = Parser()
    parser.parse_logs(".")
    created_block_df, committed_block_df, uncommit_df = parser.get_metrics_data()
    print(created_block_df)
    print(committed_block_df)