import json
import os
import glob
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any
from tqdm import tqdm
import concurrent.futures

def _process_file(json_file: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Processes a single JSON file and extracts graph statistics."""
    try:
        parts = json_file.split(os.sep)
        category = None
        if 'Malware_4' in parts:
            category = 'Malware_4'
        elif 'Benign' in parts:
            category = 'Benign'
        else:
            return None 

        with open(json_file, 'r') as f:
            data = json.load(f)

        file_stats = {
            'has_fcg': False,
            'fcg_nodes': 0,
            'fcg_edges': 0,
            'cfgs': []
        }

        if ('function_edges' in data and 
            isinstance(data['function_edges'], list) and 
            len(data['function_edges']) == 2 and
            isinstance(data['function_edges'][0], list)): 
            
            file_stats['has_fcg'] = True
            file_stats['fcg_nodes'] = data.get('function_count', 0)
            file_stats['fcg_edges'] = len(data['function_edges'][0])
            
            if 'control_flow_edges' in data:
                for func_id, cfg_data in data['control_flow_edges'].items():
                    if (isinstance(cfg_data, dict) and
                        'block_edges' in cfg_data and
                        isinstance(cfg_data['block_edges'], list) and
                        len(cfg_data['block_edges']) >= 1 and
                        isinstance(cfg_data['block_edges'][0], list)):
                        
                        cfg_nodes = cfg_data.get('block_number', 0)
                        cfg_edges = len(cfg_data['block_edges'][0])
                        file_stats['cfgs'].append({'nodes': cfg_nodes, 'edges': cfg_edges})

        if not file_stats['has_fcg'] and not file_stats['cfgs']:
             return None

        return category, file_stats

    except Exception as e:
        print(f"\nError processing {json_file}: {str(e)}") 
        return None


def analyze_function_call_graphs(json_root: str = "/projects/hchen5_proj/json/", max_workers: Optional[int] = None) -> Dict:
    """Analyze function call graphs and control flow graphs in malware and benign samples using multithreading."""
    
    stats = {
        'Malware_4': {
            'fcg_count': 0,
            'total_fcg_nodes': 0, 
            'total_fcg_edges': 0,
            'cfg_count': 0,
            'total_cfg_nodes': 0,
            'total_cfg_edges': 0
        },
        'Benign': {
            'fcg_count': 0,
            'total_fcg_nodes': 0,
            'total_fcg_edges': 0, 
            'cfg_count': 0,
            'total_cfg_nodes': 0,
            'total_cfg_edges': 0
        }
    }

    all_json_files = []
    print("Collecting file paths...")
    for category in ['Malware_4', 'Benign']:
        for year in range(2012, 2023):
            pattern = os.path.join(json_root, category, str(year), '**', '*.json')
            all_json_files.extend(glob.glob(pattern, recursive=True))
    
    print(f"Found {len(all_json_files)} JSON files to process.")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(_process_file, json_file): json_file for json_file in all_json_files}
        for future in tqdm(concurrent.futures.as_completed(future_to_file), total=len(all_json_files), desc="Processing JSON files"):
            result = future.result()
            if result:
                results.append(result)

    print("\nAggregating results...")
    for category, file_stats in tqdm(results, desc="Aggregating results"):
        if category in stats:
            if file_stats['has_fcg']:
                stats[category]['fcg_count'] += 1
                stats[category]['total_fcg_nodes'] += file_stats['fcg_nodes']
                stats[category]['total_fcg_edges'] += file_stats['fcg_edges']
            
            for cfg_stat in file_stats['cfgs']:
                stats[category]['cfg_count'] += 1
                stats[category]['total_cfg_nodes'] += cfg_stat['nodes']
                stats[category]['total_cfg_edges'] += cfg_stat['edges']


    # Calculate averages
    final_results = {}
    for category in stats:
        fcg_count = stats[category]['fcg_count']
        cfg_count = stats[category]['cfg_count']
        
        final_results[category] = {
            'function_call_graphs': {
                'count': fcg_count,
                'avg_nodes': stats[category]['total_fcg_nodes'] / fcg_count if fcg_count > 0 else 0,
                'avg_edges': stats[category]['total_fcg_edges'] / fcg_count if fcg_count > 0 else 0
            },
            'control_flow_graphs': {
                'count': cfg_count,
                'avg_nodes': stats[category]['total_cfg_nodes'] / cfg_count if cfg_count > 0 else 0,
                'avg_edges': stats[category]['total_cfg_edges'] / cfg_count if cfg_count > 0 else 0
            }
        }

    return final_results

def print_statistics():
    """Print the statistics for both malware and benign samples."""
    results = analyze_function_call_graphs(max_workers=10)
    
    print("\nFunction Call Graph and Control Flow Graph Statistics\n")
    print("=" * 60)
    
    for category in ['Malware_4', 'Benign']:
        print(f"\n{category} Statistics:")
        print("-" * 30)
        
        fcg_stats = results[category]['function_call_graphs']
        cfg_stats = results[category]['control_flow_graphs']
        
        print(f"\nFunction Call Graphs:")
        print(f"  Total Count: {fcg_stats['count']:,}")
        print(f"  Average Nodes: {fcg_stats['avg_nodes']:.2f}")
        print(f"  Average Edges: {fcg_stats['avg_edges']:.2f}")
        
        print(f"\nControl Flow Graphs:")
        print(f"  Total Count: {cfg_stats['count']:,}")
        print(f"  Average Nodes: {cfg_stats['avg_nodes']:.2f}")
        print(f"  Average Edges: {cfg_stats['avg_edges']:.2f}")

if __name__ == "__main__":
    print_statistics()
